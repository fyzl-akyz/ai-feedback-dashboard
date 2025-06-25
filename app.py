import streamlit as st
import requests
import pandas as pd
from supabase import create_client, Client
import json
from datetime import datetime, timedelta
import hashlib
import secrets
import time

# Güvenlik konfigürasyonu
SESSION_TIMEOUT = 30  # dakika
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION = 15  # dakika

def hash_password(password):
    """Şifreyi güvenli hash'le"""
    return hashlib.sha256(password.encode()).hexdigest()

def get_config():
    """Güvenli konfigürasyon yönetimi"""
    try:
        # Şifre hash'ini kontrol et
        password_hash = st.secrets.get("PASSWORD_HASH")
        if not password_hash:
            # Eğer hash yoksa, düz metinden oluştur (geçiş dönemi için)
            plain_password = st.secrets.get("PASSWORD", "")
            password_hash = hash_password(plain_password)
        
        return {
            'SUPABASE_URL': st.secrets["SUPABASE_URL"],
            'SUPABASE_KEY': st.secrets["SUPABASE_KEY"],
            'N8N_WEBHOOK_URL': st.secrets["N8N_WEBHOOK_URL"],
            'USERNAME': st.secrets["USERNAME"],
            'PASSWORD_HASH': password_hash,
            'SECRET_KEY': st.secrets.get("SECRET_KEY", secrets.token_hex(32))
        }
    except KeyError as e:
        st.error(f"⚠️ Konfigürasyon hatası! Secret bulunamadı: {e}")
        st.info("Lütfen Streamlit dashboard'unda Secrets bölümünü kontrol edin.")
        st.stop()

def init_security():
    """Güvenlik durumunu başlat"""
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = {}
    if 'session_data' not in st.session_state:
        st.session_state.session_data = {}

def is_account_locked():
    """Hesap kilitlenme kontrolü"""
    client_id = st.session_state.get('client_id', 'unknown')
    if client_id in st.session_state.login_attempts:
        attempts_data = st.session_state.login_attempts[client_id]
        if attempts_data['count'] >= MAX_LOGIN_ATTEMPTS:
            lockout_time = attempts_data['locked_until']
            if datetime.now() < lockout_time:
                return True, lockout_time
            else:
                # Kilit süresi doldu, sıfırla
                del st.session_state.login_attempts[client_id]
    return False, None

def record_failed_login():
    """Başarısız giriş denemesini kaydet"""
    client_id = st.session_state.get('client_id', 'unknown')
    now = datetime.now()
    
    if client_id not in st.session_state.login_attempts:
        st.session_state.login_attempts[client_id] = {'count': 0, 'locked_until': None}
    
    st.session_state.login_attempts[client_id]['count'] += 1
    
    if st.session_state.login_attempts[client_id]['count'] >= MAX_LOGIN_ATTEMPTS:
        st.session_state.login_attempts[client_id]['locked_until'] = now + timedelta(minutes=LOCKOUT_DURATION)

def is_session_valid():
    """Oturum geçerliliği kontrolü"""
    if 'logged_in' not in st.session_state or not st.session_state.logged_in:
        return False
    
    if 'login_time' not in st.session_state:
        return False
    
    # Session timeout kontrolü
    login_time = st.session_state.login_time
    if datetime.now() - login_time > timedelta(minutes=SESSION_TIMEOUT):
        st.session_state.logged_in = False
        st.session_state.clear()
        return False
    
    return True

def log_activity(action, details=""):
    """Aktivite logları (güvenlik monitoring için)"""
    if 'activity_log' not in st.session_state:
        st.session_state.activity_log = []
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'user': st.session_state.get('username', 'Unknown'),
        'action': action,
        'details': details,
        'ip': st.session_state.get('client_id', 'Unknown')
    }
    
    st.session_state.activity_log.append(log_entry)
    
    # Son 100 log'u tut
    if len(st.session_state.activity_log) > 100:
        st.session_state.activity_log = st.session_state.activity_log[-100:]

def check_login():
    """Gelişmiş giriş kontrolü"""
    init_security()
    
    # Client ID oluştur (basit fingerprinting)
    if 'client_id' not in st.session_state:
        st.session_state.client_id = hashlib.md5(f"{st.session_state}_{time.time()}".encode()).hexdigest()
    
    if not is_session_valid():
        show_login()
        return False
    return True

def show_login():
    """Güvenli giriş ekranı"""
    config = get_config()
    
    # Hesap kilit kontrolü
    is_locked, unlock_time = is_account_locked()
    
    st.markdown("""
    <div style="text-align: center; padding: 50px;">
        <h1>🔐 AI Feedback Sistemi</h1>
        <h3>Güvenli Giriş</h3>
    </div>
    """, unsafe_allow_html=True)
    
    if is_locked:
        st.error(f"🚫 Hesap geçici olarak kilitlendi. Kilit açılma zamanı: {unlock_time.strftime('%H:%M:%S')}")
        st.info("Çok fazla başarısız giriş denemesi yapıldı. Lütfen bekleyin.")
        return
    
    # Giriş formu
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.container():
            st.markdown("### 👤 Kullanıcı Girişi")
            
            # Rate limiting uyarısı
            client_id = st.session_state.get('client_id', 'unknown')
            attempts = st.session_state.login_attempts.get(client_id, {}).get('count', 0)
            if attempts > 0:
                remaining = MAX_LOGIN_ATTEMPTS - attempts
                st.warning(f"⚠️ Kalan deneme hakkı: {remaining}")
            
            username = st.text_input("👤 Kullanıcı Adı", placeholder="Kullanıcı adınızı girin")
            password = st.text_input("🔒 Şifre", type="password", placeholder="Şifrenizi girin")
            
            col_login, col_clear = st.columns([2, 1])
            
            with col_login:
                if st.button("🚀 Giriş Yap", use_container_width=True):
                    if username and password:
                        hashed_password = hash_password(password)
                        
                        if username == config['USERNAME'] and hashed_password == config['PASSWORD_HASH']:
                            # Başarılı giriş
                            st.session_state.logged_in = True
                            st.session_state.username = username
                            st.session_state.login_time = datetime.now()
                            
                            # Başarılı giriş sonrası attempt'leri temizle
                            if client_id in st.session_state.login_attempts:
                                del st.session_state.login_attempts[client_id]
                            
                            log_activity("LOGIN_SUCCESS", f"User {username} logged in successfully")
                            st.success("✅ Giriş başarılı! Hoş geldiniz!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            # Başarısız giriş
                            record_failed_login()
                            log_activity("LOGIN_FAILED", f"Failed login attempt for user {username}")
                            st.error("❌ Kullanıcı adı veya şifre hatalı!")
                    else:
                        st.error("❌ Lütfen tüm alanları doldurun!")
            
            with col_clear:
                if st.button("🗑️ Temizle"):
                    st.rerun()
            
            # Güvenlik bilgilendirmesi
            st.markdown("---")
            st.info("🛡️ Bu sistem SHA256 ile yüksek güvenlikli oturum yönetimi kullanır")
            st.caption(f"⏰ Oturum süresi: {SESSION_TIMEOUT} dakika")

def show_logout_button():
    """Güvenli çıkış butonu"""
    if st.sidebar.button("🚪 Çıkış Yap"):
        log_activity("LOGOUT", f"User {st.session_state.get('username')} logged out")
        st.session_state.logged_in = False
        st.session_state.clear()
        st.rerun()

def show_security_info():
    """Güvenlik bilgilerini göster"""
    with st.sidebar.expander("🔒 Güvenlik Bilgileri"):
        login_time = st.session_state.get('login_time')
        if login_time:
            remaining_time = SESSION_TIMEOUT - (datetime.now() - login_time).total_seconds() / 60
            st.write(f"⏰ Kalan süre: {remaining_time:.0f} dk")
        
        st.write(f"👤 Kullanıcı: {st.session_state.get('username', 'N/A')}")
        st.write(f"🕒 Giriş: {login_time.strftime('%H:%M') if login_time else 'N/A'}")

# Supabase client
@st.cache_resource
def init_supabase():
    config = get_config()
    return create_client(config['SUPABASE_URL'], config['SUPABASE_KEY'])

def main():
    st.set_page_config(
        page_title="AI Feedback Sistemi",
        page_icon="🤖",
        layout="wide"
    )
    
    # Giriş kontrolü
    if not check_login():
        return
    
    # Ana uygulama
    config = get_config()
    
    st.title("🤖 AI Görev Analizi Feedback Sistemi")
    st.markdown("AI'ın kararlarını düzelterek sistemin öğrenmesini sağlayın")

    # Sidebar - Kullanıcı bilgileri
    st.sidebar.header(f"👋 Hoş geldin, {st.session_state.get('username', 'Kullanıcı')}")
    st.sidebar.success("🔐 Güvenli oturum aktif")
    st.sidebar.info("📡 Konfigürasyon hazır")
    
    show_security_info()
    show_logout_button()
    
    if st.sidebar.button("🔄 Yenile"):
        log_activity("PAGE_REFRESH", "User refreshed the page")
        st.rerun()

    # Ana içerik
    col1, col2 = st.columns([2, 1])

    with col1:
        st.header("📋 Feedback Bekleyen Görevler")

        try:
            supabase = init_supabase()

            # Feedback bekleyen görevleri getir
            response = supabase.table("rask_logs") \
                .select("*") \
                .eq("feedback_status", "pending") \
                .order("message_date", desc=True) \
                .limit(20) \
                .execute()

            tasks = response.data

            if tasks:
                for task in tasks:
                    with st.expander(f"📨 {task['original_message'][:50]}..."):
                        col_a, col_b = st.columns(2)

                        with col_a:
                            st.markdown("**📊 Görev Detayları:**")
                            st.write(f"**Kullanıcı:** {task['user_first_name']} {task['user_last_name']}")
                            st.write(f"**Grup:** {task['group']} ")
                            st.write(f"**Mesaj:** {task['original_message']}")
                            utc_time = datetime.fromisoformat(task['message_date'].replace('Z', '+00:00'))
                            local_time = utc_time + timedelta(hours=2)
                            st.write(f"**Tarih:** {local_time.strftime('%H:%M %d.%m.%Y')}")

                        with col_b:
                            st.markdown("**🤖 AI Kararı:**")
                            st.write(f"**Departman:** {task['responsible_unit']}")
                            st.write(f"**Tür:** {task['task_type']}")
                            st.write(f"**Öncelik:** {task['priority']}")
                            st.write(f"**Güven:** {task['confidence_score']:.1%}")

                        # Düzeltme formu
                        if st.button(f"✏️ Düzelt", key=f"edit_{task['id']}"):
                            st.session_state[f"editing_{task['id']}"] = True
                            log_activity("EDIT_START", f"Started editing task {task['id']}")

                        if st.session_state.get(f"editing_{task['id']}", False):
                            st.markdown("---")
                            st.markdown("**✅ Doğru Değerler:**")

                            col_x, col_y, col_z = st.columns(3)

                            with col_x:
                                correct_responsible = st.selectbox(
                                    "Sorumlu Birim",
                                    ["Planlayıcı", "Bölge Yöneticisi", "Diğer"],
                                    index=["Planlayıcı", "Bölge Yöneticisi", "Diğer"].index(
                                        task['responsible_unit']),
                                    key=f"resp_{task['id']}"
                                )

                            with col_y:
                                correct_type = st.selectbox(
                                    "Görev Türü",
                                    ["hastalık", "istek", "şikayet", "bilgi", "gecikme", "diğer"],
                                    index=["hastalık", "istek", "şikayet", "bilgi", "gecikme", "diğer"].index(
                                        task['task_type']),
                                    key=f"type_{task['id']}"
                                )

                            with col_z:
                                correct_priority = st.selectbox(
                                    "Öncelik",
                                    ["düşük", "orta", "yüksek"],
                                    index=["düşük", "orta", "yüksek"].index(task['priority']),
                                    key=f"prio_{task['id']}"
                                )

                            reason = st.text_area("Düzeltme Sebebi", key=f"reason_{task['id']}")
                            corrector_name = st.text_input("Düzelten Kişi", value=st.session_state.get('username', ''), key=f"corrector_{task['id']}")

                            col_save, col_cancel = st.columns(2)

                            with col_save:
                                if st.button(f"💾 Kaydet", key=f"save_{task['id']}"):
                                    # Feedback gönder
                                    feedback_data = {
                                        "task_id": task['id'],
                                        "original_message": task['original_message'],
                                        "correction": {
                                            "responsible": correct_responsible,
                                            "type": correct_type,
                                            "priority": correct_priority
                                        },
                                        "reason": reason,
                                        "corrector_name": corrector_name,
                                        "corrector_session": st.session_state.get('client_id', 'unknown')
                                    }

                                    try:
                                        response = requests.post(
                                            config['N8N_WEBHOOK_URL'],
                                            json=feedback_data,
                                            headers={"Content-Type": "application/json"},
                                            timeout=10  # Timeout ekle
                                        )

                                        if response.status_code == 200:
                                            log_activity("FEEDBACK_SENT", f"Feedback sent for task {task['id']}")
                                            st.success("✅ Feedback başarıyla gönderildi!")
                                            st.session_state[f"editing_{task['id']}"] = False
                                            st.rerun()
                                        else:
                                            log_activity("FEEDBACK_ERROR", f"HTTP {response.status_code} for task {task['id']}")
                                            st.error(f"❌ Hata: {response.status_code}")
                                    except Exception as e:
                                        log_activity("FEEDBACK_ERROR", f"Connection error for task {task['id']}: {str(e)}")
                                        st.error(f"❌ Bağlantı hatası: {str(e)}")

                            with col_cancel:
                                if st.button(f"❌ İptal", key=f"cancel_{task['id']}"):
                                    st.session_state[f"editing_{task['id']}"] = False
                                    log_activity("EDIT_CANCEL", f"Cancelled editing task {task['id']}")
                                    st.rerun()
            else:
                st.info("🎉 Harika! Şu anda feedback bekleyen görev yok.")

        except Exception as e:
            log_activity("DATABASE_ERROR", f"Supabase connection error: {str(e)}")
            st.error(f"❌ Supabase bağlantı hatası: {str(e)}")

    with col2:
        st.header("📊 İstatistikler")

        try:
            supabase = init_supabase()

            # İstatistikler
            total_response = supabase.table("rask_logs").select("id", count="exact").execute()
            pending_response = supabase.table("rask_logs").select("id", count="exact").eq("feedback_status",
                                                                                          "pending").execute()
            corrected_response = supabase.table("rask_logs").select("id", count="exact").eq("feedback_status",
                                                                                            "corrected").execute()

            total_tasks = total_response.count
            pending_tasks = pending_response.count
            corrected_tasks = corrected_response.count

            st.metric("📝 Toplam Görev", total_tasks)
            st.metric("⏳ Bekleyen", pending_tasks)
            st.metric("✅ Düzeltilen", corrected_tasks)

            if total_tasks > 0:
                accuracy = ((total_tasks - corrected_tasks) / total_tasks) * 100
                st.metric("🎯 AI Doğruluk", f"{accuracy:.1f}%")

            # Son aktiviteler
            st.subheader("🕒 Son Aktiviteler")
            recent_response = supabase.table("rask_logs") \
                .select("original_message, responsible_unit, message_date") \
                .order("message_date", desc=True) \
                .limit(5) \
                .execute()

            for task in recent_response.data:
                st.text(f"📨 {task['original_message'][:30]}...")
                st.caption(f"🏢 {task['responsible_unit']} • {task['message_date'][:10]}")
                st.divider()

        except Exception as e:
            log_activity("STATS_ERROR", f"Statistics error: {str(e)}")
            st.error(f"❌ İstatistik hatası: {str(e)}")

if __name__ == "__main__":
    main()
