self.addEventListener("push", (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch {
    payload = { body: event.data ? event.data.text() : "" };
  }

  const severity = String(payload.severity || "").toLowerCase();
  const title = payload.title || "Aegrail";
  const options = {
    body: payload.body || "",
    badge: "/dashboard/favicon-32x32.png",
    data: {
      url: payload.url || "/dashboard/"
    },
    icon: "/dashboard/icon.png",
    requireInteraction: severity === "critical" || severity === "high",
    tag: payload.finding_id || payload.rule_id || "aegrail-finding"
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const targetURL = event.notification.data && event.notification.data.url ? event.notification.data.url : "/dashboard/";
  event.waitUntil(
    clients.matchAll({ includeUncontrolled: true, type: "window" }).then((clientList) => {
      for (const client of clientList) {
        if ("navigate" in client && "focus" in client) {
          return client.navigate(targetURL).then((focused) => focused.focus());
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(targetURL);
      }
      return undefined;
    })
  );
});
