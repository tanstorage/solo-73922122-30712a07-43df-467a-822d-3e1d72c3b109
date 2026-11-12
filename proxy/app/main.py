"""
HTTP/1.1 反向代理（asyncio + h11，单进程）

职责：
  * 仅放行 POST /events，其余请求拒绝并关闭入站连接；
  * 完整校验入站帧格式（重复 Content-Length、TE/CL 并存、非法分块、正文超限等），
    校验通过后丢弃原始分帧，重建单一 Content-Length 再转发；
  * 固定上游，连接池容量 2，每条连接同一时刻只处理一笔；
  * 从发送起总限 2 秒；超时 / 客户端断连即销毁上游连接，迟到响应不会交给下一调用者；
  * 客户端在“等待名额 / 建连中 / 建连完成交接”任一时点断连，本次获取都立即
    结束：未发送的上报绝不继续转发，占用的名额准确归还且不重复释放，后续正常
    上报无需重启即可继续；
  * 只有完整收齐带 Content-Length 的响应才把连接归还连接池。

h11 是 sans-IO 解析器：它只负责字节 <-> 事件，所有 IO 与策略由本模块实现。
"""

from __future__ import annotations

import asyncio
import copy
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

import h11

# --------------------------------------------------------------------------- #
# 常量与配置
# --------------------------------------------------------------------------- #

MAX_BODY = 64 * 1024                      # 单请求正文硬上限 64 KiB
POOL_CAPACITY = 2                         # 上游连接池容量
UPSTREAM_TIMEOUT = 2.0                    # 从发送起总限时 2 秒
IDLE_TIMEOUT = 30.0                       # 入站连接空闲超时（防僵死占用）
READ_QUEUE_HWM = 8                        # 入站字节块队列高水位（背压）
READ_QUEUE_LWM = 2
READ_BLOCK = 65536

UPSTREAM_HOST = os.environ.get("UPSTREAM_HOST", "upstream")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "8000"))
# 建连前可控延迟（秒），用于在慢建连场景下编排断连交错回归；默认 0 不影响生产。
UPSTREAM_CONNECT_DELAY = float(os.environ.get("UPSTREAM_CONNECT_DELAY", "0"))
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))

# RFC 7230 §6.1 逐跳头，禁止被代理转发；另含常见的非标准 Proxy-Connection。
HOP_BY_HOP = frozenset(
    b"""
    connection keep-alive proxy-authenticate proxy-authorization te trailer
    transfer-encoding upgrade proxy-connection content-length host
    """.split()
)

log = logging.getLogger("smuggling-guard-proxy")


# --------------------------------------------------------------------------- #
# 自定义异常
# --------------------------------------------------------------------------- #


class RejectRequest(Exception):
    """入站请求未通过校验。status 为回给客户端的 HTTP 状态码，连接随后关闭。"""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class ClientGone(Exception):
    """客户端在请求处理完成前断连。"""


class UpstreamError(Exception):
    """上游通信失败（连接、协议、对端关闭等）。"""


class CloseAfterReply(Exception):
    """错误响应已发送，只需关闭入站连接，不再写第二份响应。"""


# --------------------------------------------------------------------------- #
# 上游连接与连接池
# --------------------------------------------------------------------------- #


@dataclass
class UpstreamConn:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    conn: h11.Connection
    busy: bool = False
    closed: bool = False
    # 名额是否已被扣减（仅在连接销毁的 _free_slot 中置位）。
    # 健康连接的多次 release 不改变该标志，保证复用路径不重复记账。
    slot_freed: bool = False
    requests_served: int = 0

    def close(self) -> None:
        """销毁连接。调用后该对象永远不会再回到池中。"""
        if self.closed:
            return
        self.closed = True
        try:
            self.writer.close()
        except OSError:
            pass
        # h11 状态同步清理，防止迟到事件残留（连接本身被丢弃，不会复用）。
        try:
            self.conn.send(h11.ConnectionClosed())
        except h11.LocalProtocolError:
            pass


class UpstreamPool:
    """容量固定为 2 的上游连接池；每条连接由 busy 保证同一时刻仅处理一笔。

    名额（``_active``）的记账规则：
      * ``_take_slot`` 决定新建时预占一个名额；
      * 建连成功且连接交接给调用方后，该名额由连接对象持有；健康连接每次
        成功交换后可被多次 ``release`` 回池复用，名额始终只算一次；
      * 名额的真正扣减只发生在 ``_free_slot``（连接销毁），每条连接至多一次
        （``slot_freed`` 保证幂等），因此重复销毁 / 释放不会重复扣名额；
      * 建连失败、或建连协程在等待期间被取消（客户端断连），名额当场归还，
        任何已建成的半成品连接立即销毁，绝不回流池内。
    """

    def __init__(self, host: str, port: int, capacity: int = POOL_CAPACITY,
                 connector=None, connect_delay: float = UPSTREAM_CONNECT_DELAY):
        self._host = host
        self._port = port
        self._capacity = capacity
        # 可注入的建连函数，便于回归测试精确控制“建连变慢 / 建连完成时点”。
        self._connector = connector or asyncio.open_connection
        self._connect_delay = connect_delay
        self._idle: list[UpstreamConn] = []
        self._active = 0
        self._cond = asyncio.Condition()

    async def acquire(self) -> UpstreamConn:
        # 最多按容量次数尝试，避免空闲连接被对端静默关闭时反复拿到死连接。
        for _ in range(self._capacity + 1):
            uc = await self._take_slot()
            if uc is not None:
                # 活性预检：对端若已半关闭，reader 会立刻 EOF。
                if not uc.closed and not uc.reader.at_eof():
                    uc.busy = True
                    return uc
                await self.destroy(uc)  # 死连接销毁并补名额，继续尝试
                continue

            # 无空闲连接且池未满：名额已在 _take_slot 中预占。
            # 慢建连期间本协程可能因客户端断连被取消，所有出口都必须
            # 准确归还名额；半成品连接必须销毁，不能让后续转发拿到它。
            reader = writer = None
            try:
                if self._connect_delay:
                    await asyncio.sleep(self._connect_delay)
                reader, writer = await self._connector(
                    self._host, self._port)
            except asyncio.CancelledError:
                await self._abort_new_connection(reader, writer)
                raise
            except BaseException as exc:
                await self._abort_new_connection(reader, writer)
                if isinstance(exc, OSError):
                    raise UpstreamError(
                        f"connect upstream failed: {exc}") from exc
                raise
            return UpstreamConn(reader, writer, h11.Connection(h11.CLIENT),
                                busy=True)
        raise UpstreamError("pool exhausted while recovering dead connections")

    async def _abort_new_connection(
        self,
        reader: Optional[asyncio.StreamReader],
        writer: Optional[asyncio.StreamWriter],
    ) -> None:
        """建连失败 / 被取消后的统一清理：销毁半成品连接并归还预占名额。"""
        if writer is not None:
            # abort() 立即关闭底层 socket，避免慢建连取消后留下半开连接
            # 与未回收的 transport（close() 仍会尝试 flush 缓冲）。
            if writer.transport is not None and not writer.is_closing():
                writer.transport.abort()
            try:
                writer.close()
            except OSError:
                pass
        async with self._cond:
            self._active -= 1
            self._cond.notify()

    async def _take_slot(self) -> Optional[UpstreamConn]:
        async with self._cond:
            while True:
                if self._idle:
                    return self._idle.pop()
                if self._active < self._capacity:
                    self._active += 1
                    return None
                await self._cond.wait()

    async def release(self, uc: UpstreamConn) -> None:
        """完整成功交换后归还；损坏 / 已关闭的连接直接销毁。

        幂等语义：``release`` 是“归还复用”，同一条健康连接在其生命周期内
        会被多次 release（每次成功交换后一次），名额始终由它持有、不重复计数；
        真正的名额扣减只发生在 ``_free_slot``（连接销毁）时，且每条连接
        至多一次，杜绝重复释放。
        """
        uc.busy = False
        if uc.closed:
            await self._free_slot(uc)
            return
        async with self._cond:
            if uc.slot_freed:
                # 已走销毁路径的连接绝不回流空闲池。
                return
            if uc not in self._idle:
                self._idle.append(uc)
            self._cond.notify()

    async def destroy(self, uc: UpstreamConn) -> None:
        """失败路径：销毁连接并腾出池名额。重复调用安全且只生效一次。"""
        uc.close()
        await self._free_slot(uc)

    async def _free_slot(self, uc: UpstreamConn) -> None:
        """唯一的名额扣减点：每条连接至多扣一次，防止重复释放。"""
        async with self._cond:
            if uc.slot_freed:
                return
            uc.slot_freed = True
            # 若连接此刻还挂在空闲池里（理论上不应发生），先摘除再扣名额。
            try:
                self._idle.remove(uc)
            except ValueError:
                pass
            self._active -= 1
            self._cond.notify()

    async def aclose(self) -> None:
        async with self._cond:
            for uc in self._idle:
                uc.close()
                if not uc.slot_freed:
                    uc.slot_freed = True
                    self._active -= 1
            self._idle.clear()
            self._cond.notify_all()


# --------------------------------------------------------------------------- #
# 上游交换：重建 Content-Length 转发，且只接受 Content-Length 成帧的响应
# --------------------------------------------------------------------------- #


async def exchange_upstream(
    pool: UpstreamPool,
    uc: UpstreamConn,
    method: bytes,
    target: bytes,
    headers: list[tuple[bytes, bytes]],
    body: bytes,
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    """在一条已获取的上游连接上完成一次完整的请求/响应交换。

    任何异常都意味着该连接可能处于帧错位状态，调用方必须销毁它，
    从而保证“迟到响应”绝不会被后续调用者读到。
    """
    # 重建单一 Content-Length，彻底剥离入站分块/歧义分帧。
    out_headers = [(k, v) for k, v in headers if k.lower() not in HOP_BY_HOP]
    out_headers.append((b"content-length", str(len(body)).encode("ascii")))
    out_headers.append((b"host", f"{UPSTREAM_HOST}:{UPSTREAM_PORT}".encode("ascii")))

    try:
        uc.writer.write(uc.conn.send(h11.Request(
            method=method, target=target, headers=out_headers)))
        if body:
            uc.writer.write(uc.conn.send(h11.Data(data=body)))
        uc.writer.write(uc.conn.send(h11.EndOfMessage()))
        await uc.writer.drain()
    except (OSError, h11.LocalProtocolError) as exc:
        raise UpstreamError(f"send upstream failed: {exc}") from exc

    # ---- 读取完整响应 -----------------------------------------------------
    status_code: Optional[int] = None
    resp_headers: list[tuple[bytes, bytes]] = []
    chunks: list[bytes] = []
    saw_response = False

    while True:
        event = await _up_next_event(uc)

        if isinstance(event, h11.InformationalResponse):
            # 1xx 属于请求处理过程中的临时状态，代理不向上游之外的语义做承诺，直接忽略。
            continue

        if isinstance(event, h11.Response):
            saw_response = True
            status_code = event.status_code
            resp_headers = list(event.headers)
            continue

        if isinstance(event, h11.Data):
            chunks.append(bytes(event.data))
            continue

        if isinstance(event, h11.EndOfMessage):
            break

        if event is h11.ConnectionClosed:
            raise UpstreamError("upstream closed before complete response")

    if not saw_response or status_code is None:
        raise UpstreamError("upstream produced no response")

    # 只信任 Content-Length 成帧：chunked / 无长度 / 重复长度一律不复用连接。
    cl_headers = [v for k, v in resp_headers if k.lower() == b"content-length"]
    te_headers = [v for k, v in resp_headers if k.lower() == b"transfer-encoding"]
    if te_headers or len(cl_headers) != 1:
        raise UpstreamError("upstream response is not Content-Length framed")
    try:
        declared = int(cl_headers[0].decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise UpstreamError("upstream sent malformed Content-Length") from exc

    payload = b"".join(chunks)
    if declared != len(payload):
        raise UpstreamError("upstream Content-Length does not match body")

    uc.requests_served += 1
    try:
        uc.conn.start_next_cycle()
    except h11.LocalProtocolError as exc:
        raise UpstreamError(f"upstream connection not reusable: {exc}") from exc
    return status_code, resp_headers, payload


async def _up_read(uc: UpstreamConn, n: int = READ_BLOCK) -> bytes:
    try:
        data = await uc.reader.read(n)
    except (ConnectionError, OSError) as exc:
        raise UpstreamError(f"read upstream failed: {exc}") from exc
    return data


async def _up_next_event(uc: UpstreamConn):
    """驱动 h11 CLIENT 连接解析下一个事件。"""
    while True:
        try:
            event = uc.conn.next_event()
        except h11.RemoteProtocolError as exc:
            raise UpstreamError(f"upstream protocol error: {exc}") from exc
        if event is h11.NEED_DATA:
            data = await _up_read(uc)
            try:
                uc.conn.receive_data(data)
            except h11.RemoteProtocolError as exc:
                raise UpstreamError(f"upstream protocol error: {exc}") from exc
            continue
        return event


# --------------------------------------------------------------------------- #
# 入站校验
# --------------------------------------------------------------------------- #


def validate_framing(headers: list[tuple[bytes, bytes]]) -> tuple[bool, Optional[int]]:
    """校验请求头的分帧声明。

    返回 (是否 chunked, Content-Length 值)。任何歧义 / 非法形式都抛 RejectRequest，
    调用方拒绝并关闭连接，请求体不会被继续读取、更不会到达上游。
    """
    cl_values = [v for k, v in headers if k.lower() == b"content-length"]
    te_values = [v for k, v in headers if k.lower() == b"transfer-encoding"]

    # 1) 重复 Content-Length（含单头逗号分隔的多个值）——走私经典入口。
    if len(cl_values) > 1 or any(b"," in v for v in cl_values):
        raise RejectRequest(400, "duplicate Content-Length")
    cl: Optional[int] = None
    if cl_values:
        raw = cl_values[0].strip()
        # 只接受纯非负十进制整数；h11 本身也会拒绝负号/非数字，这里显式给出策略。
        if not raw.isdigit():
            raise RejectRequest(400, "malformed Content-Length")
        cl = int(raw)

    # 2) TE 与 CL 并存——RFC 7230 §3.3.3 要求必须拒绝（h11 0.16 不会自动拒绝！）。
    if te_values and cl is not None:
        raise RejectRequest(400, "Transfer-Encoding and Content-Length both present")

    # 3) 重复 TE 头，或不是 chunked（gzip/identity/压缩链等都不接受）。
    if len(te_values) > 1:
        raise RejectRequest(400, "duplicate Transfer-Encoding")
    if te_values:
        if te_values[0].strip().lower() != b"chunked":
            raise RejectRequest(400, "only Transfer-Encoding: chunked is accepted")
        return True, None

    # 无 TE 无 CL：按空正文处理（POST /events 允许空体）。
    return False, cl


# --------------------------------------------------------------------------- #
# 入站连接（低层 Protocol + 字节队列，便于及时发现断连与背压）
# --------------------------------------------------------------------------- #


_EOF = object()


async def _silent_await_cancel(task: asyncio.Task) -> None:
    """取消任务并吞掉 CancelledError；已完成则取回结果避免未取异常告警。"""
    if task.done():
        try:
            task.result()
        except Exception:  # noqa: BLE001 - 清理路径，结果无意义
            pass
        return
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):  # noqa: BLE001
        pass


class InboundProtocol(asyncio.Protocol):
    def __init__(self, pool: UpstreamPool):
        self._pool = pool
        self._h11 = h11.Connection(
            h11.SERVER, max_incomplete_event_size=MAX_BODY)
        self._queue: asyncio.Queue = asyncio.Queue(READ_QUEUE_HWM)
        self._transport: Optional[asyncio.Transport] = None
        self._peer = "?"
        self._closed_event = asyncio.Event()
        self._idle_task: Optional[asyncio.Task] = None
        self._main_task: Optional[asyncio.Task] = None
        self._graceful_eof = False  # reject() 已优雅半关闭时，结束回调不再硬关闭

    # ---- asyncio.Protocol 回调 ------------------------------------------- #

    def connection_made(self, transport: asyncio.Transport) -> None:
        self._transport = transport
        self._peer = "%s:%s" % transport.get_extra_info("peername")[:2]
        self._idle_task = asyncio.create_task(self._idle_watchdog())
        # 主处理协程：Protocol 只负责把字节塞进队列，解析与转发由 run() 驱动。
        self._main_task = asyncio.create_task(self.run())
        self._main_task.add_done_callback(self._main_done)
        log.info("inbound connected %s", self._peer)

    def _main_done(self, task: asyncio.Task) -> None:
        if not task.cancelled() and task.exception() is not None:
            log.exception("inbound task crashed %s", task.exception())
        # 优雅半关闭（write_eof）已排队时不能再 close，否则内核会用 RST 顶替 FIN。
        if self._graceful_eof:
            return
        if self._transport is not None and not self._transport.is_closing():
            self._transport.close()

    def data_received(self, data: bytes) -> None:
        # 队列高水位背压：暂停读取，等主循环消费到低水位再恢复。
        self._queue.put_nowait(data)
        if self._queue.qsize() >= READ_QUEUE_HWM:
            self._transport.pause_reading()

    def eof_received(self) -> Optional[bool]:
        self._queue.put_nowait(_EOF)
        return None  # 交由 connection_lost 关闭

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self._closed_event.set()
        self._queue.put_nowait(_EOF)
        if self._idle_task:
            self._idle_task.cancel()

    async def _idle_watchdog(self) -> None:
        try:
            await asyncio.sleep(IDLE_TIMEOUT)
            log.warning("idle timeout %s", self._peer)
            self._transport.close()
        except asyncio.CancelledError:
            pass

    # ---- 字节读取与 h11 驱动 --------------------------------------------- #

    async def _fill(self) -> None:
        item = await self._queue.get()
        if item is _EOF:
            try:
                self._h11.receive_data(b"")
            except h11.RemoteProtocolError:
                pass
            return
        try:
            self._h11.receive_data(item)
        except h11.RemoteProtocolError as exc:
            raise RejectRequest(400, f"protocol error: {exc}") from exc
        # 消费到低水位以下后恢复读取，形成背压闭环。
        if self._transport is not None and not self._transport.is_reading() \
                and self._queue.qsize() <= READ_QUEUE_LWM:
            self._transport.resume_reading()

    async def next_event(self):
        while True:
            try:
                event = self._h11.next_event()
            except h11.RemoteProtocolError as exc:
                raise RejectRequest(400, f"protocol error: {exc}") from exc
            if event is h11.NEED_DATA:
                await self._fill()
                continue
            if event is h11.PAUSED:  # 理论上 SERVER 角色不会出现，防御性处理
                await asyncio.sleep(0)
                continue
            return event

    def _send(self, data: bytes) -> None:
        if self._transport is None or self._transport.is_closing():
            raise ClientGone("client transport closed")
        try:
            self._transport.write(data)
        except (ConnectionError, OSError) as exc:
            raise ClientGone(str(exc)) from exc

    # ---- 回包 / 拒绝 ------------------------------------------------------ #

    def send_simple(self, status: int, message: bytes, keep_alive: bool) -> None:
        headers = [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(message)).encode("ascii")),
            (b"connection", b"keep-alive" if keep_alive else b"close"),
        ]
        self._send(self._h11.send(h11.Response(status_code=status, headers=headers)))
        if message:
            self._send(self._h11.send(h11.Data(data=message)))
        self._send(self._h11.send(h11.EndOfMessage()))

    async def reject(self, status: int, reason: str) -> None:
        """拒绝并关闭：尽力回一个错误响应，刷新后半关闭，保证客户端能读到。"""
        log.warning("reject %s status=%s reason=%s", self._peer, status, reason)
        try:
            # 注意：send(Response) 本身就返回状态行+响应头字节，必须写出去，
            # 只 send(EndOfMessage) 会让客户端收到一个没有响应的空连接。
            self._send(self._h11.send(h11.Response(
                status_code=status,
                headers=[
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", b"0"),
                    (b"connection", b"close"),
                ],
            )))
            self._send(self._h11.send(h11.EndOfMessage()))
            # 让出事件循环，确保 transport 把缓冲字节交付内核后再半关闭（FIN）。
            # 不能 pause_reading：那会触发 connection_lost，使 run() 的 finally
            # 抢先硬关闭并 RST 掉刚写的错误响应。
            await asyncio.sleep(0)
            # 1 秒后兜底硬关闭，防止对端不配合导致连接悬挂。
            loop = asyncio.get_running_loop()
            loop.call_later(1.0, self._hard_close)
            if self._transport.can_write_eof():
                self._graceful_eof = True
                self._transport.write_eof()
            else:
                self._hard_close()
        except (h11.LocalProtocolError, ClientGone, OSError, RuntimeError):
            self._hard_close()

    def _hard_close(self) -> None:
        if self._transport is not None and not self._transport.is_closing():
            try:
                self._transport.close()
            except OSError:
                pass

    # ---- 主处理循环 ------------------------------------------------------- #

    async def run(self) -> None:
        try:
            await self._loop()
        except ClientGone:
            log.info("client gone %s", self._peer)
        except CloseAfterReply:
            # 错误响应已经写出，这里只保证连接关闭。
            pass
        except RejectRequest as exc:
            await self.reject(exc.status, exc.reason)
        except Exception:
            log.exception("fatal inbound error %s", self._peer)
            if self._transport is not None and not self._transport.is_closing():
                self._transport.close()
        finally:
            if not self._graceful_eof and self._transport is not None \
                    and not self._transport.is_closing():
                self._transport.close()

    async def _loop(self) -> None:
        while True:
            request = await self.next_event()
            if isinstance(request, h11.ConnectionClosed):
                return

            assert isinstance(request, h11.Request)
            method = request.method
            target = request.target
            headers = list(request.headers)

            # 路由白名单：仅 POST /events，其余一律拒绝并关闭。
            if target != b"/events":
                raise RejectRequest(404, f"path not allowed: {target.decode('ascii', 'replace')}")
            if method != b"POST":
                raise RejectRequest(405, f"method not allowed: {method.decode('ascii', 'replace')}")

            chunked, declared_cl = validate_framing(headers)

            # Expect: 100-continue —— 仅在分帧校验通过后才放行继续发送正文。
            if any(k.lower() == b"expect" and b"100-continue" in v.lower()
                   for k, v in headers):
                self._send(self._h11.send(
                    h11.InformationalResponse(status_code=100, headers=[])))

            # 声明长度已知且超限，可在读取前直接拒绝，避免浪费带宽。
            if not chunked and declared_cl is not None and declared_cl > MAX_BODY:
                raise RejectRequest(413, f"body exceeds {MAX_BODY} bytes")

            body = await self._read_body(chunked, declared_cl)
            log.info(
                "validated request %s target=/events bytes=%d chunked=%s",
                self._peer, len(body), chunked,
            )

            keep_alive = _wants_keep_alive(request.http_version, headers)
            await self._forward(headers, body, keep_alive)

            if not keep_alive:
                return
            self._h11.start_next_cycle()

    async def _read_body(self, chunked: bool, declared_cl: Optional[int]) -> bytes:
        """完整读取并校验正文；支持 TCP 分片与流水线（h11 缓冲下一请求字节）。"""
        buf = bytearray()
        while True:
            event = await self.next_event()
            if isinstance(event, h11.EndOfMessage):
                break
            if not isinstance(event, h11.Data):
                raise RejectRequest(400, "unexpected event while reading body")
            buf.extend(event.data)
            if len(buf) > MAX_BODY:
                raise RejectRequest(413, f"body exceeds {MAX_BODY} bytes")
        # 非 chunked 且带 CL：h11 已按长度截断，这里做双保险确认。
        if not chunked and declared_cl is not None and len(buf) != declared_cl:
            raise RejectRequest(400, "truncated or mismatched Content-Length body")
        # 反走私关键检查：当前请求完整结束后，区分“合法流水线缓冲”与“走私残片”。
        self._reject_smuggled_tail()
        return bytes(buf)

    def _reject_smuggled_tail(self) -> None:
        """请求体结束后，h11 内部若残留字节，必须能解析成下一条合法请求。

        合法流水线（含跨 TCP 段的半截下一请求前缀）放行；任何无法成帧的
        残片（CL.TE/TE.CL 走私、夹带后台请求等）一律拒绝并关闭连接。
        探测在 h11 连接的深拷贝上进行，主连接状态不被修改。
        """
        try:
            buffer = bytes(self._h11._receive_buffer)  # noqa: SLF001
        except AttributeError:
            return
        if not buffer.strip(b"\r\n"):
            return  # 仅空行前导，容忍
        probe = copy.deepcopy(self._h11)
        try:
            probe.send(h11.Response(
                status_code=200,
                headers=[(b"content-length", b"0")]))
            probe.send(h11.EndOfMessage())
            probe.start_next_cycle()
            event = probe.next_event()
        except (h11.RemoteProtocolError, h11.LocalProtocolError) as exc:
            raise RejectRequest(
                400, f"trailing bytes not forming valid next request: {exc}")
        # Request = 完整的下一请求（流水线）；NEED_DATA = 半截前缀，等更多字节。
        if not isinstance(event, h11.Request) and event is not h11.NEED_DATA:
            raise RejectRequest(
                400, "unexpected trailing bytes after request body")

    # ---- 转发 ------------------------------------------------------------- #

    async def _acquire_abortable(self) -> UpstreamConn:
        """获取上游连接，客户端在任一阶段断连都立即中止本次获取。

        三个断连时点全部覆盖：
          1. 等待池名额：``acquire`` 卡在条件变量上，取消即可，名额从未预占；
          2. 建连中：``acquire`` 卡在 open_connection 上，取消后由池统一
             销毁半成品连接并归还名额，不会泄漏；
          3. 建连完成与断连同拍（交接点）：``acquire`` 已经把新连接交接出来，
             此时若客户端已不在，必须当场销毁该连接并放弃上报，
             绝不能带着一个“已放弃的请求”继续向上游发送。
        """
        acquired = asyncio.create_task(self._pool.acquire())
        closed = asyncio.create_task(self._closed_event.wait())
        try:
            await asyncio.wait({acquired, closed},
                               return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            acquired.cancel()
            closed.cancel()
            raise
        finally:
            if not closed.done():
                closed.cancel()

        client_gone = self._closed_event.is_set()

        if not acquired.done():
            # 时点 1/2：获取尚未结束（等名额或建连中），取消并由池清理名额。
            acquired.cancel()
            await _silent_await_cancel(acquired)
            if client_gone:
                raise ClientGone(
                    "client closed while waiting for upstream connection")
            # 理论不可达：两任务都未完成。防御性向上传播取消。
            raise UpstreamError("upstream acquire aborted without result")

        # 获取已完成：无论成败都先取回，避免未取异常告警。
        if acquired.exception() is not None:
            exc = acquired.exception()
            if client_gone:
                raise ClientGone(
                    "client closed during upstream acquire") from exc
            if isinstance(exc, UpstreamError):
                raise exc
            raise UpstreamError(str(exc)) from exc

        uc = acquired.result()
        if client_gone:
            # 时点 3：连接刚建好、尚未发送任何上报字节，客户端已经断连。
            # 销毁连接并归还名额；本次上报到此结束，绝不继续转发。
            await self._pool.destroy(uc)
            raise ClientGone(
                "client closed right when upstream connection completed")
        return uc

    async def _forward(
        self,
        headers: list[tuple[bytes, bytes]],
        body: bytes,
        keep_alive: bool,
    ) -> None:
        # 统一截止时刻：从首次发送起 2 秒，期间无论是否重试都不突破该预算。
        deadline = time.monotonic() + UPSTREAM_TIMEOUT
        last_exc: Optional[Exception] = None

        for attempt in (1, 2):
            uc = await self._acquire_abortable()
            # 排队等待名额期间 closed 竞速任务已被取消，必须在真正占用连接、
            # 发送任何上游字节之前再查一次断连标志：否则“等名额时掉线”的请求
            # 会在拿到名额后被照常转发（已放弃上报泄漏到上游）。
            if self._closed_event.is_set():
                await self._pool.destroy(uc)
                raise ClientGone(
                    "client closed while queued for upstream slot")
            exchange_task = asyncio.create_task(exchange_upstream(
                self._pool, uc, b"POST", b"/events", headers, body))
            closed_task = asyncio.create_task(self._closed_event.wait())
            timed_out = False
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                else:
                    try:
                        async with asyncio.timeout(remaining):
                            await asyncio.wait(
                                {exchange_task, closed_task},
                                return_when=asyncio.FIRST_COMPLETED)
                    except (asyncio.TimeoutError, TimeoutError):
                        timed_out = True
            finally:
                closed_task.cancel()

            try:
                # 1) 客户端先断连：取消交换、销毁上游连接后向上抛 ClientGone。
                if not exchange_task.done() and self._closed_event.is_set():
                    exchange_task.cancel()
                    await _silent_await_cancel(exchange_task)
                    await self._pool.destroy(uc)
                    raise ClientGone("client closed during upstream exchange")

                # 2) 交换自身先完成（成功或上游错误），优先采用它的结果。
                if exchange_task.done() and not timed_out:
                    try:
                        status, resp_headers, payload = exchange_task.result()
                    except UpstreamError as exc:
                        await self._pool.destroy(uc)
                        # 首笔失败（死连接/半开/协议错误）：用全新连接在剩余预算内重试一次。
                        if attempt == 1 and deadline - time.monotonic() > 0:
                            log.warning(
                                "upstream exchange failed %s: %s; retrying once",
                                self._peer, exc)
                            last_exc = exc
                            continue
                        log.warning("upstream ERROR %s: %s; conn destroyed",
                                    self._peer, exc)
                        await self._reply_error(
                            502, b"bad gateway\n", keep_alive=False)
                        raise CloseAfterReply("502 sent; close inbound") from exc
                    # 交换恰好完成与客户端断连同拍：响应无法送达，连接仍销毁。
                    if self._closed_event.is_set():
                        await self._pool.destroy(uc)
                        raise ClientGone("client closed right after exchange")
                    await self._pool.release(uc)
                    self._reply_upstream(status, resp_headers, payload, keep_alive)
                    return

                # 3) 超时（含重试后预算耗尽）：取消交换并销毁，迟到响应随连接丢弃。
                if timed_out:
                    await _silent_await_cancel(exchange_task)
                    await self._pool.destroy(uc)
                    elapsed = (time.monotonic() - (deadline - UPSTREAM_TIMEOUT)) * 1000
                    log.warning(
                        "upstream TIMEOUT %s elapsed=%.0fms conn destroyed",
                        self._peer, elapsed)
                    await self._reply_error(
                        504, b"upstream timeout\n", keep_alive=False)
                    raise CloseAfterReply("504 sent; close inbound")

                # 理论不可达：两任务都未完成且未超时。防御性按上游错误处理。
                await _silent_await_cancel(exchange_task)
                await self._pool.destroy(uc)
                raise CloseAfterReply("unexpected wait state; close inbound")
            finally:
                if not exchange_task.done():
                    exchange_task.cancel()
                    await _silent_await_cancel(exchange_task)

        # 重试后仍失败（理论上不会走到，防御性兜底）。
        await self._reply_error(502, b"bad gateway\n", keep_alive=False)
        raise CloseAfterReply(f"retry exhausted: {last_exc}")

    def _reply_upstream(
        self,
        status: int,
        headers: list[tuple[bytes, bytes]],
        payload: bytes,
        keep_alive: bool,
    ) -> None:
        clean = [(k, v) for k, v in headers if k.lower() not in HOP_BY_HOP]
        clean.append((b"content-length", str(len(payload)).encode("ascii")))
        clean.append((b"connection", b"keep-alive" if keep_alive else b"close"))
        self._send(self._h11.send(h11.Response(
            status_code=status, headers=clean)))
        if payload:
            self._send(self._h11.send(h11.Data(data=payload)))
        self._send(self._h11.send(h11.EndOfMessage()))

    async def _reply_error(self, status: int, message: bytes,
                           keep_alive: bool) -> None:
        try:
            self.send_simple(status, message, keep_alive)
        except (ClientGone, h11.LocalProtocolError, OSError):
            pass


def _wants_keep_alive(http_version: bytes,
                      headers: list[tuple[bytes, bytes]]) -> bool:
    if http_version == b"1.0":
        return any(k.lower() == b"connection" and b"keep-alive" in v.lower()
                   for k, v in headers)
    # HTTP/1.1 默认保持，除非显式 close。
    return not any(k.lower() == b"connection" and b"close" in v.lower()
                   for k, v in headers)


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #


async def serve() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    pool = UpstreamPool(UPSTREAM_HOST, UPSTREAM_PORT, POOL_CAPACITY)
    loop = asyncio.get_running_loop()

    server = await loop.create_server(
        lambda: InboundProtocol(pool), LISTEN_HOST, LISTEN_PORT)
    addr = server.sockets[0].getsockname()
    log.info("proxy listening on %s, upstream=%s:%s, pool=%d, timeout=%.1fs",
             addr, UPSTREAM_HOST, UPSTREAM_PORT, POOL_CAPACITY, UPSTREAM_TIMEOUT)

    try:
        async with server:
            await server.serve_forever()
    finally:
        await pool.aclose()


def main() -> None:
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
