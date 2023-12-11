import asyncio

class FactorHandler:
    """
        # Example usage:
        factor_value = your_factor
        key_value = your_key
        factor_handler_obj = FactorHandler(factor_value, key_value)
        setup_result = await factor_handler_obj.setup()
        print(setup_result)
        derive_result = await factor_handler_obj.derive(your_params)
        print(derive_result)
    """
    def __init__(self, factor, key=None):
        self.factor = factor
        self.key = key

    async def setup(self):
        result = await self.factor()

        if self.key:
            params = await result['params'](key=self.key)
            result['params'] = lambda: asyncio.ensure_future(params)

            output = await result['output']()
            result['output'] = lambda: asyncio.ensure_future(output)

        return result

    async def derive(self, params):
        result = await self.factor(params)

        if self.key:
            params = await result['params'](key=self.key)
            result['params'] = lambda: asyncio.ensure_future(params)

            output = await result['output']()
            result['output'] = lambda: asyncio.ensure_future(output)

        return lambda: asyncio.ensure_future(result)