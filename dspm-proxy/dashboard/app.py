"""Real-time DSPM dashboard. Run with:

    streamlit run dashboard/app.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from proxy.config import DB_PATH
from proxy.db import get_connection, init_db

st.set_page_config(page_title="DSPM Shadow-AI Egress Monitor", layout="wide")
init_db()

st_autorefresh(interval=5000, key="dspm_autorefresh")

TYPE_COLORS = {
    "workstation": "#4C78A8",
    "ot_sensor": "#F58518",
    "other": "#72B7B2",
    "unknown": "#B0B0B0",
}


@st.cache_data(ttl=2)
def load_events() -> pd.DataFrame:
    with get_connection(DB_PATH) as conn:
        df = pd.read_sql_query("SELECT * FROM egress_events ORDER BY id DESC", conn)
    return df


st.title("Shadow-AI Egress Monitor")
st.caption("Live view of outbound traffic intercepted by the DSPM proxy and classified by the local NLP engine.")

df = load_events()

col1, col2, col3 = st.columns(3)
col1.metric("Total Outbound Requests", len(df))
col2.metric("Blocked Shadow-AI Leaks", int((df["action"] == "blocked").sum()) if not df.empty else 0)
col3.metric("Monitored Devices", df["source_ip"].nunique() if not df.empty else 0)

st.divider()

left, right = st.columns([3, 2])

with left:
    st.subheader("Recent Blocked Events")
    blocked = df[df["action"] == "blocked"].head(50) if not df.empty else df
    if blocked.empty:
        st.info("No blocked egress events yet.")
    else:
        display = blocked[
            ["timestamp", "source_ip", "device_label", "destination_url", "entity_type", "confidence_score", "flagged_content"]
        ].copy()
        display["device_label"] = display["device_label"].fillna("—")
        display = display.rename(
            columns={
                "timestamp": "Timestamp",
                "source_ip": "Source IP",
                "device_label": "Device",
                "destination_url": "Destination",
                "entity_type": "Entity",
                "confidence_score": "Confidence",
                "flagged_content": "Flagged Content",
            }
        )
        st.dataframe(display, use_container_width=True, hide_index=True)

with right:
    st.subheader("Blocked Leaks by Device")
    if df.empty or (df["action"] == "blocked").sum() == 0:
        st.info("No data to chart yet.")
    else:
        blocked_df = df[df["action"] == "blocked"].copy()
        blocked_df["device_type"] = blocked_df["device_type"].fillna("unknown")
        blocked_df["device_label"] = blocked_df["device_label"].fillna(blocked_df["source_ip"])
        grouped = (
            blocked_df.groupby(["device_label", "device_type"]).size().reset_index(name="blocked_count")
            .sort_values("blocked_count", ascending=True)
        )
        fig = px.bar(
            grouped,
            x="blocked_count",
            y="device_label",
            color="device_type",
            orientation="h",
            color_discrete_map=TYPE_COLORS,
            labels={"blocked_count": "Blocked Events", "device_label": "Device", "device_type": "Device Type"},
        )
        fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=380)
        st.plotly_chart(fig, use_container_width=True)

st.divider()
st.subheader("All Traffic (most recent first)")
if df.empty:
    st.info("No traffic intercepted yet. Point a device at the proxy to see events here.")
else:
    all_traffic = df[["timestamp", "source_ip", "device_label", "destination_url", "method", "action", "classification"]].head(200).copy()
    all_traffic["device_label"] = all_traffic["device_label"].fillna("—")
    st.dataframe(all_traffic, use_container_width=True, hide_index=True)
