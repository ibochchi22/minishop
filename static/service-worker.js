self.addEventListener("install", (event) => {
  console.log("✅ Service Worker установлен");
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  console.log("🚀 Service Worker активирован");
});

// ❌ Не кэшируем — всё всегда идёт из сети
self.addEventListener("fetch", (event) => {
  event.respondWith(
    fetch(event.request).catch(() => {
      return new Response(
        "<h1 style='text-align:center;margin-top:50px;font-family:sans-serif;'>⚠️ Требуется интернет-соединение</h1>",
        { headers: { "Content-Type": "text/html" } }
      );
    })
  );
});


// 📢 Получение и отображение пуш-уведомлений
self.addEventListener("push", function (event) {
  const data = event.data ? event.data.json() : {};
  const title = data.title || "Новое уведомление";
  const options = {
    body: data.body || "",
    icon: "/static/icons/icon-192.png",
    badge: "/static/icons/icon-192.png",
    data: data.url || "/"
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// 📲 Переход по уведомлению
self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  event.waitUntil(clients.openWindow(event.notification.data));
});
