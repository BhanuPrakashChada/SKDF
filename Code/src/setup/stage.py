import asyncio

async def setup(factor, key=None):
    result = await factor()

    if key:
        params = await result['params'](key=key)
        result['params'] = lambda: asyncio.ensure_future(params)

        output = await result['output']()
        result['output'] = lambda: asyncio.ensure_future(output)

    return result

async def derive(factor, params, key=None):
    result = await factor(params)

    if key:
        params = await result['params'](key=key)
        result['params'] = lambda: asyncio.ensure_future(params)

        output = await result['output']()
        result['output'] = lambda: asyncio.ensure_future(output)

    return lambda: asyncio.ensure_future(result)

factor = {'setup': setup, 'derive': derive}