from typing import Any

import jwt
import requests
from jwt.exceptions import InvalidTokenError


class SYMKey:
    """替代 jwkest.jwk.SYMKey"""

    def __init__(self, key: str):
        self.key = key


class JWS:
    """替代 jwkest.jws.JWS"""
    def verify_compact(self, token: str, keys: list[SYMKey], algorithm: str = 'HS256') -> dict[str, Any]:
        """
        模拟 jwkest JWS.verify_compact 方法
        只进行基础的签名验证，其他验证留给上层业务逻辑
        """
        print(f"开始验证 JWT token，算法: {algorithm}")
        print(f"可用密钥数量: {len(keys)}")

        for idx, key in enumerate(keys):
            try:
                print(f"尝试密钥 {idx + 1}")

                # 模拟 jwkest 的宽松验证模式
                # 只验证签名和基本格式，不验证时间相关字段
                payload = jwt.decode(
                    token,
                    key.key,
                    algorithms=[algorithm],
                    options={
                        "verify_signature": True,  # 验证签名（核心）
                        "verify_exp": False,  # 不验证过期时间（由上层处理）
                        "verify_nbf": False,  # 不验证生效时间
                        "verify_iat": False,  # 不验证签发时间
                        "verify_aud": False,  # 不验证受众（由上层处理）
                        "verify_iss": False,  # 不验证签发者（由上层处理）
                        "require_exp": False,  # 不要求包含过期时间
                        "require_iat": False,  # 不要求包含签发时间
                        "require_nbf": False  # 不要求包含生效时间
                    }
                )

                print(f"✅ 密钥 {idx + 1} 验证成功!")
                print(f"Token payload 字段: {list(payload.keys())}")
                return payload

            except jwt.InvalidSignatureError as e:
                print(f"❌ 密钥 {idx + 1}: 签名验证失败 - {e}")
                continue
            except jwt.DecodeError as e:
                print(f"❌ 密钥 {idx + 1}: Token 解码失败 - {e}")
                continue
            except Exception as e:
                print(f"❌ 密钥 {idx + 1}: 其他错误 - {type(e).__name__}: {e}")
                continue

        raise NoSuitableSigningKeys("没有合适的签名密钥能够验证此 token")

class NoSuitableSigningKeys(Exception):
    """替代 jwkest.jws.NoSuitableSigningKeys"""
    pass


def load_jwks_from_url(url: str, timeout: int = 10) -> dict[str, Any]:
    """替代 jwkest.jwk.load_jwks_from_url"""
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise ValueError(f"无法从 {url} 加载 JWKS: {e}")


# RSA 密钥处理
class RSAKey:
    """处理 RSA 公钥"""

    def __init__(self, jwk_data: dict[str, Any]):
        self.key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk_data)


def verify_jwt_with_jwks(token: str, jwks_url: str, algorithm: str = 'RS256') -> dict[str, Any]:
    """使用 JWKS URL 验证 JWT"""
    jwks_data = load_jwks_from_url(jwks_url)

    # 尝试所有密钥
    for jwk in jwks_data.get('keys', []):
        try:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
            payload = jwt.decode(token, public_key, algorithms=[algorithm])
            return payload
        except InvalidTokenError:
            continue

    raise NoSuitableSigningKeys("没有合适的签名密钥")
