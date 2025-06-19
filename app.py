import streamlit as st
import requests
import pandas as pd
from supabase import create_client, Client
import json
from datetime import datetime
import hashlib

# Güvenli konfigürasyon - Streamlit secrets kullan
def get_config():
    try:
        return {
            'SUPABASE_URL': st.secrets["SUPABASE_URL"],
            'SUPABASE_KEY': st.secrets["SUPABASE_KEY"],
            'N8N_WEBHOOK_URL': st.secrets["N8N_WEBHOOK_URL"],
            'USERNAME': st.secrets["USERNAME"],
            'PASSWORD': st.secrets["PASSWORD"]
        }
    except KeyError as e:
        st.error(f"⚠️ Konfigürasyon hatası! Secret bulunamadı: {e}")
        st.info("Lütfen Streamlit dashboard'unda Secrets bölümünü kontrol edin.")
        st.stop()

# Giriş kontrolü
def check_login():
    """Kullanıcı giriş kontrolü"""
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    if not st.session_state.logged_in:
        show_login()
        return False
    return True

def show_login():
    """Giriş ekranını göster"""
    config = get_config()
    
    st.markdown("""
    <div style="text-align: center; padding: 50px;">
        <h1>🔐 AI Feedback Sistemi</h1>
        <h3>Lütfen giriş yapın</h3>
    </div>
    """, unsafe_allow_html=True)
    
    # Giriş formu
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.container():
            st.markdown("### 👤 Kullanıcı Girişi")
            
            username = st.text_input("👤 Kullanıcı Adı", placeholder="Kullanıcı adınızı girin")
            password = st.text_input("🔒 Şifre", type="password", placeholder="Şifrenizi girin")
            
            col_login, col_clear = st.columns([2, 1])
            
            with col_login:
                if st.button("🚀 Giriş Yap", use_container_width=True):
                    if username == config['USERNAME'] and password == config['PASSWORD']:
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.success("✅ Giriş başarılı! Hoş geldiniz!")
                        st.rerun()
                    else:
                        st.error("❌ Kullanıcı adı veya şifre hatalı!")
            
            with col_clear:
                if st.button("🗑️ Temizle"):
                    st.rerun()

def show_logout_button():
    """Çıkış butonu göster"""
    if st.sidebar.button("🚪 Çıkış Yap"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()

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

    # Sidebar - Kullanıcı bilgileri ve çıkış
    st.sidebar.header(f"👋 Hoş geldin, {st.session_state.get('username', 'Kullanıcı')}")
    st.sidebar.success("🔐 Güvenli oturum aktif")
    st.sidebar.info("📡 Konfigürasyon hazır")
    
    show_logout_button()
    
    if st.sidebar.button("🔄 Yenile"):
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
                            st.write(f"**Tarih:** {datetime.fromisoformat(task['message_date'].replace('Z', '+00:00')).strftime('%H:%M %d.%m.%Y')}")

                        with col_b:
                            st.markdown("**🤖 AI Kararı:**")
                            st.write(f"**Departman:** {task['responsible_unit']}")
                            st.write(f"**Tür:** {task['task_type']}")
                            st.write(f"**Öncelik:** {task['priority']}")
                            st.write(f"**Güven:** {task['confidence_score']:.1%}")

                        # Düzeltme formu
                        if st.button(f"✏️ Düzelt", key=f"edit_{task['id']}"):
                            st.session_state[f"editing_{task['id']}"] = True

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
                                        "corrector_name": corrector_name
                                    }

                                    try:
                                        response = requests.post(
                                            config['N8N_WEBHOOK_URL'],
                                            json=feedback_data,
                                            headers={"Content-Type": "application/json"}
                                        )

                                        if response.status_code == 200:
                                            st.success("✅ Feedback başarıyla gönderildi!")
                                            st.session_state[f"editing_{task['id']}"] = False
                                            st.rerun()
                                        else:
                                            st.error(f"❌ Hata: {response.status_code}")
                                    except Exception as e:
                                        st.error(f"❌ Bağlantı hatası: {str(e)}")

                            with col_cancel:
                                if st.button(f"❌ İptal", key=f"cancel_{task['id']}"):
                                    st.session_state[f"editing_{task['id']}"] = False
                                    st.rerun()
            else:
                st.info("🎉 Harika! Şu anda feedback bekleyen görev yok.")

        except Exception as e:
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
            st.error(f"❌ İstatistik hatası: {str(e)}")

if __name__ == "__main__":
    main()
