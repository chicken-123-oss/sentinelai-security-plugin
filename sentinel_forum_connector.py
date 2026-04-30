import time
import requests
import json

# -------------------- 配置区域 --------------------
# 插件 API 基础地址和认证令牌
SENTINEL_API = "http://127.0.0.1:8787/api/v1"
INGEST_TOKEN = "dev-ingest-token"  # 如已修改，请替换

# -------------------- 核心功能：事件注入 --------------------
def send_forum_event_to_sentinel(action, actor_ip="1.2.3.4", payload=""):
    """将论坛操作转换为安全事件，并发送给 SentinelAI"""
    
    # 定义事件结构
    event = {
        "source": "world-war-iv-forum",
        "category": "content",
        "trustLabel": "low",
        "severityHint": "medium",
        "actor": {
            "type": "ip",
            "id": actor_ip,
            "ip": actor_ip
        },
        "asset": {
            "kind": "forum",
            "id": action.get('topic_id', 'unknown')
        },
        "payload": {
            "action_type": action.get('type', 'unknown'),
            "user": action.get('user', 'anonymous'),
            "body": payload
        }
    }

    headers = {
        "Authorization": f"Bearer {INGEST_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(f"{SENTINEL_API}/events/ingest", 
                                headers=headers, 
                                json=event, 
                                timeout=5)
        if response.status_code == 201:
            print(f"✅ 事件已发送: {action.get('type')} by {action.get('user')}")
        else:
            print(f"⚠️ 事件发送失败: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"❌ 无法连接到 SentinelAI: {e}")

# -------------------- 测试与演示 --------------------
if __name__ == "__main__":
    # 场景1: 模拟一个正常发帖行为
    send_forum_event_to_sentinel(
        action={"type": "create_topic", "topic_id": "1024", "user": "demo_user"},
        payload="这是一个正常的帖子内容，讨论AI安全问题。"
    )
    time.sleep(1)

    # 场景2: 模拟一个SQL注入攻击
    send_forum_event_to_sentinel(
        action={"type": "create_topic", "topic_id": "1025", "user": "attacker_bot"},
        actor_ip="203.0.113.10",
        payload="username=admin' OR '1'='1"
    )
    print("测试事件发送完毕，请前往插件仪表盘查看。")
