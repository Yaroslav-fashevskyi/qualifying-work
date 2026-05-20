import asyncio
import time
import httpx

URL = "http://127.0.0.1:8000/api/lookup?q=1.1.1.1"

TOTAL_REQUESTS = 1000
CONCURRENCY = 10


async def worker(client, results):
    start = time.perf_counter()

    try:
        response = await client.get(URL, timeout=10)
        elapsed = time.perf_counter() - start

        results.append({
            "status": response.status_code,
            "time": elapsed
        })
    except Exception as e:
        elapsed = time.perf_counter() - start

        results.append({
            "status": "error",
            "time": elapsed,
            "error": str(e)
        })


async def main():
    results = []
    start_time = time.perf_counter()

    async with httpx.AsyncClient() as client:
        tasks = []

        for _ in range(TOTAL_REQUESTS):
            tasks.append(worker(client, results))

            if len(tasks) >= CONCURRENCY:
                await asyncio.gather(*tasks)
                tasks = []

        if tasks:
            await asyncio.gather(*tasks)

    total_time = time.perf_counter() - start_time

    successful = [r for r in results if r["status"] == 200]
    limited = [r for r in results if r["status"] == 429]
    errors = [r for r in results if r["status"] == "error"]

    avg_time = sum(r["time"] for r in successful) / len(successful) if successful else 0
    max_time = max((r["time"] for r in successful), default=0)
    min_time = min((r["time"] for r in successful), default=0)

    print("Total requests:", TOTAL_REQUESTS)
    print("Concurrency:", CONCURRENCY)
    print("Total time:", round(total_time, 3), "s")
    print("Successful:", len(successful))
    print("Rate limited:", len(limited))
    print("Errors:", len(errors))
    print("Average response time:", round(avg_time, 3), "s")
    print("Min response time:", round(min_time, 3), "s")
    print("Max response time:", round(max_time, 3), "s")


if __name__ == "__main__":
    asyncio.run(main())