import streamlit as st
import base64
import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ================= 配置区域 =================
# ⚠️ 这里不需要改，私钥依然从 Secrets 读取
# ⚠️ 确保这里的 SALT 和客户端一致
SALT_REVOKE = "MY_APP_REVOKE_SECRET_2025" 

# ================= 网页界面配置 =================
st.set_page_config(page_title="管理员发码器", page_icon="👑")

st.title("👑 超级管理员控制台")
st.markdown("---")

# 获取私钥
private_key_pem = st.secrets.get("PRIVATE_KEY")
if not private_key_pem:
    st.error("⚠️ 严重错误：未检测到私钥配置！请在后台 Secrets 设置 PRIVATE_KEY。")
    st.stop()

# ================= 核心逻辑 (完全复刻电脑版) =================
def generate_license(hwid, days, priv_pem):
    """生成与电脑版完全一致的激活码"""
    try:
        # 1. 处理日期
        if days == 0:
            expire_str = "PERMANENT"
        else:
            expire_date = datetime.datetime.now() + datetime.timedelta(days=days)
            expire_str = expire_date.strftime("%Y-%m-%d")

        # 2. 准备私钥
        key = RSA.import_key(priv_pem)
        
        # 3. 构造原始数据 (机器码|日期)
        raw_data = f"{hwid}|{expire_str}"
        msg = raw_data.encode() # 转成二进制
        
        # 4. 签名
        h = SHA256.new(msg)
        signature = pkcs1_15.new(key).sign(h)
        
        # 5. 【关键差异点】打包格式：数据###签名
        # 电脑版用的是 ### 连接，而且最后整体做了一次 Base64
        final_data = msg + b"###" + signature
        license_code = base64.b64encode(final_data).decode()
        
        return True, license_code, expire_str
    except Exception as e:
        return False, str(e), ""

def verify_revoke_code(token):
    """验证反激活码"""
    # ... (这部分逻辑不变) ...
    if not token.startswith("REVOKE#"):
        return False, "❌ 格式错误：不是有效的反激活码"
    
    parts = token.split("#")
    if len(parts) != 3:
        return False, "❌ 格式错误：代码片段不完整"
    
    old_hwid = parts[1]
    user_verify_code = parts[2]
    
    # 计算验证
    try:
        # 尝试 import hashlib，防止漏掉
        import hashlib
        calc_code = hashlib.md5((old_hwid + SALT_REVOKE).encode()).hexdigest().upper()[:8]
        
        if user_verify_code == calc_code:
            return True, old_hwid
        else:
            return False, "❌ 验证失败：校验码不匹配"
    except Exception as e:
        return False, f"验证出错: {str(e)}"

# ================= 界面显示 =================
tab1, tab2 = st.tabs(["✨ 生成激活码", "♻️ 换绑验证"])

# --- Tab 1: 生成 ---
with tab1:
    st.header("1. 生成新激活码 (兼容版)")
    hwid_input = st.text_input("请输入客户机器码", placeholder="例如: BFEBFBFF000906EA-...")
    days_input = st.number_input("有效期 (天) - 输入 0 表示永久授权", min_value=0, value=0)
    
    if st.button("生成激活码", type="primary"):
        if not hwid_input.strip():
            st.warning("请先输入机器码")
        else:
            success, result, expire_info = generate_license(hwid_input, days_input, private_key_pem)
            
            if success:
                st.success("✅ 生成成功！(已加密打包)")
                # 显示生成的长代码
                st.code(result, language="text")
                st.caption(f"有效期至: {expire_info} | 此格式已兼容客户端")
            else:
                st.error(f"❌ 生成失败: {result}")

# --- Tab 2: 换绑 ---
with tab2:
    st.header("2. 验证反激活码")
    revoke_token = st.text_input("请输入客户发来的反激活码", placeholder="REVOKE#...")
    
    if st.button("验证反激活码"):
        if not revoke_token.strip():
            st.warning("请输入代码")
        else:
            is_valid, result = verify_revoke_code(revoke_token)
            if is_valid:
                st.success("✅ 验证通过！")
                st.markdown(f"旧机器 **{result}** 证书已销毁。")
            else:
                st.error(result)
