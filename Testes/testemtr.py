import asyncio
import mtrpacket

async def trace():
    async with mtrpacket.MtrPacket() as mtr:
        for ttl in range(1, 256):
            result = await mtr.probe('www.google.com', ttl=ttl, protocol='tcp', port=33434)
            print(result)
            if result.success:
                break

asyncio.get_event_loop().run_until_complete(trace())