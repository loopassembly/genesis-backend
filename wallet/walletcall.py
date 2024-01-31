import asyncio
import subprocess



async def call_wallet(axie_id, ronin_add):
    
    ronin_address = ronin_add
    eth_address = "0x" + ronin_address[6:]
    

    try:
        result = await asyncio.create_subprocess_exec("node", "app/wallet_intigration/web_3.js", str(axie_id), str(eth_address), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await result.communicate()
        if stderr:
            print(f"An error occurred: {stderr.decode()}")
        else:
            print(stdout.decode())
        # await asyncio.sleep(5)
    except OSError as e:
        print(f"An error occurred: {e}")

# asyncio.run(call_wallet(123, 345))