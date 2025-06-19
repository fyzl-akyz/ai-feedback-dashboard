import streamlit as st
import requests
import pandas as pd
from supabase import create_client, Client
import json
from datetime import datetime

# Konfigürasyon
SUPABASE_URL = "https://your-project-id.supabase.co"
SUPABASE_KEY = "your-anon-key"
N8N_WEBHOOK_URL = "https://your-n8n-instance.app.n8n.cloud/webhook/feedback"


# Supabase client
@st.cache_resource
def init_supabase():
    return create_client(SUPABASE_URL, SUPABASE_KEY)


def main():
    st.set_page_config(
        page_title="AI Feedback Sistemi",
        page_icon="🤖",
        layout="wide"
    )

    st.title("🤖 AI Görev Analizi Feedback Sistemi")
    st.markdown("AI'ın kararlarını düzelterek sistemin öğrenmesini sağlayın")

    # Sidebar - Konfigürasyon
    st.sidebar.header("⚙️ Konfigürasyon")
    supabase_url = st.sidebar.text_input("Supabase URL", value=SUPABASE_URL)
    supabase_key = st.sidebar.text_input("Supabase Key", value=SUPABASE_KEY, type="password")
    webhook_url = st.sidebar.text_input("n8n Webhook URL", value=N8N_WEBHOOK_URL)

    if st.sidebar.button("🔄 Yenile"):
        st.rerun()

    # Ana içerik
    col1, col2 = st.columns([2, 1])

    with col1:
        st.header("📋 Feedback Bekleyen Görevler")

        if supabase_url and supabase_key:
            try:
                supabase = create_client(supabase_url, supabase_key)

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
                                corrector_name = st.text_input("Düzelten Kişi", key=f"corrector_{task['id']}")

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
                                                webhook_url,
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
        else:
            st.warning("⚠️ Supabase konfigürasyonunu sidebar'dan tamamlayın.")

    with col2:
        st.header("📊 İstatistikler")

        if supabase_url and supabase_key:
            try:
                supabase = create_client(supabase_url, supabase_key)

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
