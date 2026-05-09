import unittest

from sentinelai_plugin.llm import build_adapter
from sentinelai_plugin.models import normalize_provider


class ProviderAdaptationTests(unittest.TestCase):
    def test_china_provider_defaults_and_adapter_mapping(self):
        cases = {
            "deepseek": ("https://api.deepseek.com", "deepseek-v4-flash", "DEEPSEEK_API_KEY"),
            "glm": ("https://open.bigmodel.cn/api/paas/v4/", "glm-5", "ZAI_API_KEY"),
            "kimi": ("https://api.moonshot.ai/v1", "kimi-k2.6", "MOONSHOT_API_KEY"),
        }
        for provider_type, (endpoint, model, secret_ref) in cases.items():
            with self.subTest(provider_type=provider_type):
                provider = normalize_provider({"providerType": provider_type})
                self.assertEqual(provider["endpoint"], endpoint)
                self.assertEqual(provider["model"], model)
                self.assertEqual(provider["apiKeySecretRef"], secret_ref)
                self.assertEqual(build_adapter(provider).__class__.__name__, "OpenAICompatibleAdapter")


if __name__ == "__main__":
    unittest.main()
