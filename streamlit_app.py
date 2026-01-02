import streamlit as st
import base64
import hashlib
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

# 侧边栏：获取私钥 (从云端安全配置中读取)
# 在 Streamlit Cloud 的 Secrets 里配置 PRIVATE_KEY
private_key = st.secrets.get("PRIVATE_KEY")

if not private_key:
    st.error("⚠️ 严重错误：未检测到私钥配置！请在后台 Secrets 设置 PRIVATE_KEY。")
    st.stop()

# Tab 布局，手机上切换很方便
tab1, tab2 = st.tabs(["✨ 生成激活码", "♻️ 换绑验证"])

# --- Tab 1: 生成激活码 ---
with tab1:
    st.header("1. 生成新激活码")
    hwid_input = st.text_input("请输入客户机器码", placeholder="例如: BFEBFBFF000906EA-...")
    days_input = st.number_input("有效期 (天)", min_value=1, value=365)
    
    if st.button("生成激活码", type="primary"):
        if not hwid_input.strip():
            st.warning("请先输入机器码")
        else:
            # 构造数据
            raw_data = f"{hwid_input}|{days_input}"
            signature = sign_data(raw_data, private_key)
            
            if signature:
                final_token = f"{raw_data}|{signature}"
                st.success("✅ 生成成功！")
                st.code(final_token, language="text")
                st.caption("长按上方代码框可复制")
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
