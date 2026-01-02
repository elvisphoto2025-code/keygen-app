import streamlit as st
import base64
import hashlib
import datetime  # 新增：处理日期
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ================= 配置区域 =================
# ⚠️ 注意：私钥不要直接写在代码里！我们会放在云端的 Secrets 里
SALT_REVOKE = "MY_APP_REVOKE_SECRET_2025" 

# ================= 核心逻辑 =================
def sign_data(data_str, private_key_pem):
    """使用私钥进行RSA签名"""
    try:
        key = RSA.import_key(private_key_pem)
        h = SHA256.new(data_str.encode('utf-8'))
        signature = pkcs1_15.new(key).sign(h)
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        return None

def verify_revoke_code(token):
    """验证反激活码"""
    if not token.startswith("REVOKE#"):
        return False, "❌ 格式错误：不是有效的反激活码"
    
    parts = token.split("#")
    if len(parts) != 3:
        return False, "❌ 格式错误：代码片段不完整"
    
    old_hwid = parts[1]
    user_verify_code = parts[2]
    
    # 重新计算验证
    calc_code = hashlib.md5((old_hwid + SALT_REVOKE).encode()).hexdigest().upper()[:8]
    
    if user_verify_code == calc_code:
        return True, old_hwid
    else:
        return False, "❌ 验证失败：校验码不匹配，可能是伪造的"

# ================= 网页界面 (Streamlit) =================
st.set_page_config(page_title="管理员发码器", page_icon="👑")

st.title("👑 超级管理员控制台")
st.markdown("---")

# 侧边栏：获取私钥
private_key = st.secrets.get("PRIVATE_KEY")

if not private_key:
    st.error("⚠️ 严重错误：未检测到私钥配置！请在后台 Secrets 设置 PRIVATE_KEY。")
    st.stop()

# Tab 布局
tab1, tab2 = st.tabs(["✨ 生成激活码", "♻️ 换绑验证"])

# --- Tab 1: 生成激活码 ---
with tab1:
    st.header("1. 生成新激活码")
    hwid_input = st.text_input("请输入客户机器码", placeholder="例如: BFEBFBFF000906EA-...")
    
    # 修改点：允许输入 0，并增加提示说明
    days_input = st.number_input("有效期 (天) - 输入 0 表示永久授权", min_value=0, value=365)
    
    if st.button("生成激活码", type="primary"):
        if not hwid_input.strip():
            st.warning("请先输入机器码")
        else:
            # === 修正核心逻辑：把天数转成日期字符串 ===
            if days_input == 0:
                expire_str = "PERMANENT"
                st.info("ℹ️ 正在生成永久授权...")
            else:
                expire_date = datetime.datetime.now() + datetime.timedelta(days=days_input)
                expire_str = expire_date.strftime("%Y-%m-%d")
            
            # 构造原始数据 (机器码|过期时间)
            raw_data = f"{hwid_input}|{expire_str}"
            
            # 签名
            signature = sign_data(raw_data, private_key)
            
            if signature:
                # 最终激活码格式
                final_token = f"{raw_data}|{signature}"
                st.success("✅ 生成成功！")
                st.code(final_token, language="text")
                st.caption(f"有效期至: {expire_str}")
            else:
                st.error("❌ 签名失败，请检查私钥格式")

# --- Tab 2: 换绑验证 ---
with tab2:
    st.header("2. 验证反激活码 (换绑)")
    revoke_token = st.text_input("请输入客户发来的反激活码", placeholder="REVOKE#...")
    
    if st.button("验证反激活码"):
        if not revoke_token.strip():
            st.warning("请输入代码")
        else:
            is_valid, result = verify_revoke_code(revoke_token)
            if is_valid:
                st.success("✅ 验证通过！")
                st.markdown(f"旧机器 **{result}** 证书已销毁。")
                st.info("💡 现在您可以安全地为他的新电脑生成激活码了。")
            else:
                st.error(result)
