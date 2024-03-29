#!/usr/bin/env python

import ssl
import asyncio
import socket
import concurrent.futures
import time


class DetectIPHTTPS:

    def __init__(self) -> None:
        self.A = 0
        self.B = 0
        self.port = 443
        self.default_hostname = 'www.cloudflare.com'
        self.max_threads = 32
        self.max_processes = 16

    def start_processes(self, a: int, b: int) -> tuple:
        self.A, self.B = a, b
        with concurrent.futures.ProcessPoolExecutor(max_workers=self.max_processes) as executor:
            results = executor.map(self.start_threads, range(0, 256))
            results = tuple(data for result in results for data in result)
        return results

    def start_threads(self, c: int) -> tuple:
        context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.load_default_certs()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_url = {executor.submit(self.detect, c, d, context): d for d in range(0, 256)}
            results = (future.result() for future in concurrent.futures.as_completed(future_to_url))
            results = tuple((c, result[0], result[1]) for result in results if result[1])
        return results

    def detect(self, c: int, d: int, context: ssl.SSLContext) -> tuple:
        ip = f'{self.A}.{self.B}.{c}.{d}'
        data = ''
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            with context.wrap_socket(sock, server_hostname=self.default_hostname) as conn:
                try:
                    conn.connect((ip, self.port))
                    cert = conn.getpeercert()
                    data = tuple(i[1] for i in cert['subjectAltName'])
                    data = ' '.join(data)
                except Exception:
                    pass
        return (d, data)

    def start_eventloop(self, a: int, b: int, loop, sem: asyncio.locks.Semaphore) -> tuple:  #loop: asyncio.unix_events._UnixSelectorEventLoop | asyncio.windows_events.ProactorEventLoop
        self.A, self.B = a, b
        results = loop.run_until_complete(self.async_create_tasks(sem))
        return results

    async def async_create_tasks(self, sem: asyncio.locks.Semaphore) -> tuple:
        context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.load_default_certs()
        tasks = (self.async_timeout_detect(c, d, context, sem) for c in range(0, 256) for d in range(0, 256))
        results = await asyncio.gather(*tasks)
        return tuple(result for result in results if result[2])

    async def async_timeout_detect(self, c: int, d: int, context: ssl.SSLContext, sem: asyncio.locks.Semaphore) -> tuple:
        data = ''
        async with sem:
            try:
                data = await asyncio.wait_for(self.async_detect(c, d, context), 2.0)
            except asyncio.TimeoutError:
                pass
        return (c, d, data)

    async def async_detect(self, c: int, d: int, context: ssl.SSLContext) -> str:
        ip = f'{self.A}.{self.B}.{c}.{d}'
        data = ''
        try:
            reader, _ = await asyncio.open_connection(host=ip, port=self.port, ssl=context, server_hostname=self.default_hostname)
            cert = reader._transport.get_extra_info('peercert')
            cert_tuple = tuple(i[1] for i in cert['subjectAltName'])
            data = ' '.join(cert_tuple)
        except Exception:
            pass
        return data

    def write_to_file(self, results: tuple) -> None:
        sorted_results = sorted(results, key=lambda x: (x[0], x[1]))
        with open(f'results/{self.A}.{self.B}.x.x:{self.port}', 'w') as f:
            f.write('=====Generated by Github Actions=====\n')
            for result in sorted_results:
                f.write(f'{self.A}.{self.B}.{result[0]}.{result[1]}:{self.port} {result[2]}\n')


if __name__ == '__main__':
    mydetect = DetectIPHTTPS()

    start = time.perf_counter()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    sem = asyncio.Semaphore(512)
    # detect 202.81.0.0/16
    results_1 = mydetect.start_eventloop(202, 81, loop, sem)
    stop = time.perf_counter()
    print(stop - start)

    print(len(results_1))
    mydetect.write_to_file(results_1)

    #There are some problems when using multiprocessing in this program: too much memory is used. Using Asyncio is a more efficient way

    #socket.setdefaulttimeout(2)
    #start = time.perf_counter()
    #results_2 = mydetect.start_processes(202, 81)
    #stop = time.perf_counter()
    #print(stop - start)

    #print(len(results_2))
    #mydetect.write_to_file(results_2)
