import { useEffect, useRef, useState } from 'react';
import { wsThreatFeedUrl } from '../lib/api';

const MAX_EVENTS = 25;

export function useThreatFeed() {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);

  useEffect(() => {
    let cancelled = false;

    function connect() {
      const ws = new WebSocket(wsThreatFeedUrl());
      wsRef.current = ws;

      ws.onopen = () => !cancelled && setConnected(true);
      ws.onclose = () => {
        if (cancelled) return;
        setConnected(false);
        // Real reconnect-with-backoff, matches how a dashboard should behave
        // against a backend that restarts/redeploys.
        setTimeout(connect, 3000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (msg) => {
        try {
          const payload = JSON.parse(msg.data);
          if (payload.type === 'CONNECTED' || payload.type === 'FEED_STARTED') return;
          setEvents((prev) => [payload, ...prev].slice(0, MAX_EVENTS));
        } catch {
          // ignore malformed frame
        }
      };
    }

    connect();
    return () => {
      cancelled = true;
      wsRef.current?.close();
    };
  }, []);

  return { events, connected };
}
