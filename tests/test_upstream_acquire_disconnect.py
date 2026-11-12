"""
回归测试：上游建连变慢时，探针在获取上游连接期间断连的各种交错场景。

覆盖问题单描述的三类断连时点：
  1. 等待名额（池容量 2 被占满）时断连 —— 名额必须立刻可用，不能泄漏；
  2. 建连中（asyncio.open_connection 尚未返回）连续两次断连 ——
     两次都必须结束本次获取，随后正常上报不能一直等待；
  3. 断连恰逢建连完成（连接交接点）—— 已放弃的上报不得再转发给上游。

另含防回归保护：
  * 正常成功仍复用同一条上游连接，池容量恒为 2（无重复释放 / 名额损坏）；
  * 断连后无需重启代理即可继续上报；
  * 分帧防护与“从发送起 2 秒”期限保持有效。

仅依赖标准库 + 被测模块自身依赖的 h11，可直接：
    python -m unittest tests.test_upstream_acquire_disconnect -v
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proxy"))

from app import main as proxy_mod  # noqa: E402

# 与生产保持一致的入站空闲超时；测试全程远短于该值，避免看门狗干扰编排。
proxy_mod.IDLE_TIMEOUT = 30.0


# --------------------------------------------------------------------------- #
# 可控假上游：记录实收请求；接受连接的节奏可被测试控制
# --------------------------------------------------------------------------- #


class FakeUpstream:
    """最小 HTTP/1.1 上游：按 Content-Length 收请求，回 202，记录每次接收。"""

    def __init__(self) -> None:
        self.received: list[bytes] = []
        self.connections = 0
        self.server: asyncio.AbstractServer | None = None
        self.host = "127.0.0.1"
        self.port = 0
        # 每个新连接建立前要通过的闸门（测试用于精确编排建连完成时点）。
        self.accept_gate: asyncio.Event | None = None
        # 每次 accept 处理前的固定延迟（测试用于模拟“上游建连变慢”）。
        self.connect_delay = 0.0
        # 每笔请求读完后、回响应前要通过的闸门（测试用于让交换长期挂起）。
        self.response_gate: asyncio.Event | None = None
        self.response_delay = 0.0

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle, self.host, 0)
        sock = self.server.sockets[0]
        self.port = sock.getsockname()[1]

    async def serve(self) -> None:
        assert self.server is not None
        async with self.server:
            await self.server.serve_forever()

    def close(self) -> None:
        if self.server is not None and self.server.is_serving():
            self.server.close()

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            while True:
                # 与真实 uvicorn 一致：支持 keep-alive，连接可连续服务多笔。
                line = await reader.readline()
                if not line:
                    return
                headers = {}
                while line not in (b"\r\n", b"\n", b""):
                    if b":" in line:
                        k, v = line.split(b":", 1)
                        headers[k.strip().lower()] = v.strip()
                    line = await reader.readline()
                n = int(headers.get(b"content-length", b"0") or b"0")
                body = await reader.readexactly(n) if n else b""
                self.received.append(body)
                if self.response_delay:
                    await asyncio.sleep(self.response_delay)
                if self.response_gate is not None:
                    await self.response_gate.wait()
                payload = b'{"accepted":true}'
                writer.write(
                    b"HTTP/1.1 202 Accepted\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: " + str(len(payload)).encode()
                    + b"\r\n\r\n" + payload)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            return
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    def make_connector(self):
        """返回给 UpstreamPool 使用的可控 open_connection 替身。"""

        async def connector(host, port):
            if self.connect_delay:
                await asyncio.sleep(self.connect_delay)
            if self.accept_gate is not None:
                await self.accept_gate.wait()
            return await asyncio.open_connection(host, port)

        return connector


# --------------------------------------------------------------------------- #
# 探针侧最小 HTTP/1.1 客户端
# --------------------------------------------------------------------------- #


class ProbeClient:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self._buf = b""  # 读完上一响应时可能预读到的下一响应前缀

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port)

    def post(self, body: bytes, path: bytes = b"/events",
             extra_headers: bytes = b"") -> None:
        assert self.writer is not None
        req = (
            b"POST " + path + b" HTTP/1.1\r\nHost: probe.local\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            + extra_headers + b"\r\n" + body)
        self.writer.write(req)

    async def _readline(self) -> bytes:
        """带预读缓冲的 readline，避免 drain 响应时吞掉下一响应的状态行。"""
        assert self.reader is not None
        if b"\r\n" in self._buf:
            line, self._buf = self._buf.split(b"\r\n", 1)
            return line + b"\r\n"
        chunk = await self.reader.readline()
        if self._buf:
            line = self._buf + chunk
            self._buf = b""
            return line
        return chunk

    async def _readexactly(self, n: int) -> bytes:
        assert self.reader is not None
        if len(self._buf) >= n:
            data, self._buf = self._buf[:n], self._buf[n:]
            return data
        head = self._buf
        self._buf = b""
        return head + await self.reader.readexactly(n - len(head))

    async def read_status(self) -> int:
        line = await self._readline()
        return int(line.split(b" ", 2)[1])

    async def drain_response(self) -> None:
        """读完一个 Content-Length 响应，让连接可进入下一管线周期。"""
        length = 0
        while True:
            line = await self._readline()
            if line in (b"\r\n", b""):
                break
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1].strip())
        if length:
            await self._readexactly(length)

    def hard_disconnect(self) -> None:
        """模拟探针异常掉线：直接关闭 TCP，不读任何代理响应。"""
        if self.writer is not None:
            self.writer.transport.abort()
            self.writer = None
            self.reader = None

    async def graceful_close(self) -> None:
        if self.writer is not None:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except OSError:
                pass
            self.writer = None
            self.reader = None


# --------------------------------------------------------------------------- #
# 测试基类：拉起真实代理（in-process）+ 假上游
# --------------------------------------------------------------------------- #


class ProxyHarness(unittest.IsolatedAsyncioTestCase):

    def setUp(self) -> None:
        self.upstream = FakeUpstream()
        self.proxy_server: asyncio.AbstractServer | None = None
        self.proxy_port = 0
        self.pool: proxy_mod.UpstreamPool | None = None
        self._serve_task: asyncio.Task | None = None

    async def asyncSetUp(self) -> None:
        await self.upstream.start()
        self._serve_task = asyncio.create_task(self.upstream.serve())
        self.pool = proxy_mod.UpstreamPool(
            self.upstream.host, self.upstream.port,
            capacity=2, connector=self.upstream.make_connector())
        loop = asyncio.get_running_loop()
        self.proxy_server = await loop.create_server(
            lambda: proxy_mod.InboundProtocol(self.pool),
            "127.0.0.1", 0)
        self.proxy_port = self.proxy_server.sockets[0].getsockname()[1]

    async def asyncTearDown(self) -> None:
        if self.proxy_server is not None:
            self.proxy_server.close()
            await self.proxy_server.wait_closed()
        if self.pool is not None:
            await self.pool.aclose()
        self.upstream.close()
        if self._serve_task is not None:
            try:
                await asyncio.wait_for(self._serve_task, timeout=2)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._serve_task.cancel()

    async def new_probe(self) -> ProbeClient:
        p = ProbeClient("127.0.0.1", self.proxy_port)
        await p.connect()
        return p

    async def normal_post_succeeds(self, tag: str) -> None:
        """断连风暴之后必须成立：新探针正常上报立即成功，无需重启。"""
        body = tag.encode()
        probe = await self.new_probe()
        probe.post(body)
        status = await probe.read_status()
        await probe.drain_response()
        self.assertEqual(status, 202)
        self.assertIn(body, self.upstream.received)
        await probe.graceful_close()

    def assert_pool_healthy(self) -> None:
        """名额账目必须守恒：active 落在 [0, 容量]，空闲连接不重复计数。"""
        assert self.pool is not None
        self.assertGreaterEqual(self.pool._active, 0)
        self.assertLessEqual(self.pool._active, 2)
        self.assertLessEqual(len(self.pool._idle), 2)
        self.assertEqual(
            len({id(c) for c in self.pool._idle}), len(self.pool._idle),
            "空闲池中出现重复连接对象，说明释放路径重复归还")


# --------------------------------------------------------------------------- #
# 回归用例
# --------------------------------------------------------------------------- #


class TestDisconnectWhileAcquiring(ProxyHarness):

    async def test_double_disconnect_during_slow_connect_does_not_leak_slots(self):
        """建连变慢时连续两次断连：两次获取都必须结束，第三次正常上报不等待。"""
        self.upstream.connect_delay = 0.6

        for i in (1, 2):
            probe = await self.new_probe()
            probe.post(f"abandoned-{i}".encode())
            # 让代理进入 open_connection 的等待中再拔线。
            await asyncio.sleep(0.15)
            probe.hard_disconnect()

        # 给代理两个被取消的建连协程足够时间完成名额清理。
        await asyncio.sleep(0.3)
        self.assert_pool_healthy()
        self.assertEqual(
            self.pool._active, 0,
            "建连中取消后名额未归还：后续请求将一直等待（问题单现象 1）")

        # 无需重启：新探针的正常上报必须立刻成功。
        await self.normal_post_succeeds("surviving-report")
        self.assert_pool_healthy()

        # 已放弃的上报绝不能被转发。
        self.assertNotIn(b"abandoned-1", self.upstream.received)
        self.assertNotIn(b"abandoned-2", self.upstream.received)

    async def test_disconnect_while_waiting_for_slot_releases_waiter(self):
        """池容量 2 占满时，第三个请求在等名额期间断连，不得占住任何名额。"""
        # 响应闸门关闭：两个占用者的上游交换稳定挂起，两条车道被占满。
        gate = asyncio.Event()
        self.upstream.response_gate = gate

        holders = []
        for i in (1, 2):
            probe = await self.new_probe()
            probe.post(f"holder-{i}".encode())
            holders.append(probe)
        # 等两条上游连接都进入 busy（请求已被上游读走但响应被闸门挂住）。
        deadline = time.monotonic() + 3
        while (self.pool._active < 2
               or len(self.upstream.received) < 2) and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        self.assertEqual(self.pool._active, 2)

        waiter = await self.new_probe()
        waiter.post(b"waiter-abandoned")
        # 确定地等到代理协程进入条件变量排队，而不是靠固定 sleep 猜时序。
        deadline = time.monotonic() + 3
        while len(self.pool._cond._waiters) == 0 and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        self.assertGreater(len(self.pool._cond._waiters), 0,
                           "第三个请求没有进入名额排队")
        waiter.hard_disconnect()
        # 等到代理的排队协程被取消并退出条件变量。
        deadline = time.monotonic() + 3
        while len(self.pool._cond._waiters) > 0 and time.monotonic() < deadline:
            await asyncio.sleep(0.01)

        self.assert_pool_healthy()
        self.assertEqual(self.pool._active, 2, "等待者断连不应改变名额账目")
        self.assertNotIn(b"waiter-abandoned", self.upstream.received)

        # 放开闸门：两个占用者正常完成后，新请求必须立刻拿到名额成功。
        gate.set()
        for probe in holders:
            status = await probe.read_status()
            self.assertEqual(status, 202)
            await probe.drain_response()
            await probe.graceful_close()
        await asyncio.sleep(0.2)
        self.assert_pool_healthy()
        await self.normal_post_succeeds("after-waiter-gone")
        self.assertNotIn(b"waiter-abandoned", self.upstream.received)

    async def test_disconnect_exactly_when_connect_completes(self):
        """断连恰逢建连完成（交接点）：连接必须销毁，上报不得转发。"""
        gate = asyncio.Event()
        self.upstream.accept_gate = gate

        probe = await self.new_probe()
        probe.post(b"handoff-abandoned")

        # 等到代理的建连协程已经启动并阻塞在交接闸门前。
        await asyncio.sleep(0.15)
        # 同时放开建连并断开探针，制造“建连完成与断连同拍”的交错。
        gate.set()
        probe.hard_disconnect()

        await asyncio.sleep(0.4)
        self.assert_pool_healthy()
        self.assertEqual(
            self.pool._active, 0,
            "交接点断连后新建连接必须销毁并归还名额，不能回流池里")
        self.assertNotIn(
            b"handoff-abandoned", self.upstream.received,
            "断连恰逢建连完成时，已放弃的上报仍被转发（问题单现象 2）")

        # 代理仍然可用。
        await self.normal_post_succeeds("after-handoff")

    async def test_successful_requests_reuse_single_upstream_connection(self):
        """正常路径不变：同一条入站连接上的连续成功复用同一条上游 TCP。"""
        # 预热：先完成一笔，让上游连接回到空闲池，之后全部应命中复用。
        await self.normal_post_succeeds("warmup")
        conns_before = self.upstream.connections

        probe = await self.new_probe()
        for i in range(4):
            body = f"reuse-{i}".encode()
            probe.post(body)
            self.assertEqual(await probe.read_status(), 202)
            await probe.drain_response()
            self.assertIn(body, self.upstream.received)
        await probe.graceful_close()

        self.assert_pool_healthy()
        self.assertEqual(
            self.upstream.connections, conns_before,
            f"成功请求未复用连接，上游新建连接数增加至 "
            f"{self.upstream.connections - conns_before}")
        self.assertEqual(self.pool._active, 1)
        self.assertEqual(len(self.pool._idle), 1)

    async def test_pool_capacity_stays_two_under_mixed_disconnects(self):
        """断连与正常请求交错后，第三笔并发请求仍必须排队（容量没有被撑破）。"""
        # 先制造一次建连中断连，制造过销毁路径。
        self.upstream.connect_delay = 0.4
        gone = await self.new_probe()
        gone.post(b"early-gone")
        await asyncio.sleep(0.1)
        gone.hard_disconnect()
        await asyncio.sleep(0.6)
        self.upstream.connect_delay = 0.0
        self.assert_pool_healthy()

        # 再用并发请求验证严格两车道：占满后第三笔必须等待。
        holders = []
        for i in (1, 2):
            p = await self.new_probe()
            p.post(f"cap-holder-{i}".encode())
            holders.append(p)
        deadline = time.monotonic() + 3
        while self.pool._active < 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        self.assertEqual(self.pool._active, 2)

        third = await self.new_probe()
        third.post(b"cap-third")
        await asyncio.sleep(0.3)
        self.assertEqual(self.pool._active, 2, "容量被破坏：出现第三条上游连接")

        status = await third.read_status()
        self.assertEqual(status, 202)
        await third.drain_response()
        for p in holders:
            self.assertEqual(await p.read_status(), 202)
            await p.drain_response()
            await p.graceful_close()
        await third.graceful_close()
        self.assert_pool_healthy()

    async def test_two_second_deadline_still_enforced(self):
        """保留原期限：从发送起 2 秒未完成则 504，且之后代理仍可用。"""
        # 让上游处理变慢：通过延迟读取无法在 FakeUpstream 内配置，
        # 改为让假上游在收到请求后延迟回响应。
        async def slow_handler(reader, writer):
            try:
                line = await reader.readline()
                n = 0
                while line not in (b"\r\n", b""):
                    if line.lower().startswith(b"content-length:"):
                        n = int(line.split(b":", 1)[1].strip())
                    line = await reader.readline()
                if n:
                    await reader.readexactly(n)
                await asyncio.sleep(2.5)
                writer.write(
                    b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\n\r\n{}")
                await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except OSError:
                    pass

        loop = asyncio.get_running_loop()
        slow_server = await asyncio.start_server(slow_handler, "127.0.0.1", 0)
        slow_port = slow_server.sockets[0].getsockname()[1]
        slow_task = asyncio.create_task(slow_server.serve_forever())

        slow_pool = proxy_mod.UpstreamPool(
            "127.0.0.1", slow_port, capacity=2)
        slow_proxy = await loop.create_server(
            lambda: proxy_mod.InboundProtocol(slow_pool), "127.0.0.1", 0)
        slow_proxy_port = slow_proxy.sockets[0].getsockname()[1]
        try:
            probe = ProbeClient("127.0.0.1", slow_proxy_port)
            await probe.connect()
            probe.post(b"too-slow")
            t0 = time.monotonic()
            status = await probe.read_status()
            elapsed = time.monotonic() - t0
            self.assertEqual(status, 504)
            self.assertGreaterEqual(elapsed, 1.9)
            self.assertLessEqual(elapsed, 2.6)
            await probe.graceful_close()
        finally:
            slow_proxy.close()
            await slow_proxy.wait_closed()
            await slow_pool.aclose()
            slow_server.close()
            slow_task.cancel()

        # 504 销毁连接后，原代理的正常上报不受影响。
        await self.normal_post_succeeds("after-504")

    async def test_framing_guards_remain_intact(self):
        """保留原分帧防护：重复 Content-Length 仍被 400 拒绝且不到达上游。"""
        probe = await self.new_probe()
        probe.writer.write(
            b"POST /events HTTP/1.1\r\nHost: p\r\n"
            b"Content-Length: 4\r\nContent-Length: 9\r\n\r\nGOOD\r\nBAD")
        try:
            status = await probe.read_status()
            self.assertEqual(status, 400)
        except (ConnectionError, OSError):
            pass  # 直接断连同样符合“拒绝并关闭”语义
        await asyncio.sleep(0.1)
        self.assertNotIn(b"GOOD", self.upstream.received)
        await probe.graceful_close()
        await self.normal_post_succeeds("after-reject")


class TestPoolSlotAccounting(ProxyHarness):
    """不经过入站 HTTP，直接对连接池记账做压力 / 幂等验证。"""

    async def test_destroy_is_idempotent_under_double_release(self):
        """同一条连接被 destroy 两次（清理竞态）只能扣一次名额。"""
        uc = await self.pool.acquire()
        self.assertEqual(self.pool._active, 1)
        await self.pool.destroy(uc)
        await self.pool.destroy(uc)  # 重复销毁不得把 _active 扣成负数
        await self.pool.release(uc)  # 销毁后再 release 也不得回流 / 改动账目
        self.assertEqual(self.pool._active, 0)
        self.assertEqual(self.pool._idle, [])
        self.assert_pool_healthy()

    async def test_repeated_release_then_destroy_keeps_single_slot(self):
        """健康连接多次 release（复用）只占一个名额，最终销毁只扣一次。"""
        uc = await self.pool.acquire()
        for _ in range(3):
            await self.pool.release(uc)
        self.assertEqual(self.pool._active, 1)
        self.assertEqual(len(self.pool._idle), 1)
        # 再取出并销毁，账目归零。
        again = await self.pool.acquire()
        self.assertIs(again, uc)
        await self.pool.destroy(again)
        self.assertEqual(self.pool._active, 0)
        self.assert_pool_healthy()

    async def test_many_cancelled_connects_never_exhaust_pool(self):
        """大量“建连中取消”交错后，容量与名额始终守恒，正常获取不被阻塞。"""
        self.upstream.connect_delay = 0.15

        async def abandon_once(i: int) -> None:
            task = asyncio.create_task(self.pool.acquire())
            await asyncio.sleep(0.02 + 0.003 * i)  # 错开取消时点
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        await asyncio.gather(*(abandon_once(i) for i in range(8)))
        self.assert_pool_healthy()
        self.assertEqual(self.pool._active, 0)

        self.upstream.connect_delay = 0.0
        # 名额全部可用：连续两次获取都应立刻成功，证明没有泄漏导致永久等待。
        uc1 = await self.pool.acquire()
        uc2 = await self.pool.acquire()
        self.assertEqual(self.pool._active, 2)
        with self.assertRaises(TimeoutError):
            await asyncio.wait_for(self.pool.acquire(), timeout=0.15)
        await self.pool.destroy(uc1)
        await self.pool.destroy(uc2)
        self.assertEqual(self.pool._active, 0)
        self.assert_pool_healthy()


if __name__ == "__main__":
    unittest.main(verbosity=2)
