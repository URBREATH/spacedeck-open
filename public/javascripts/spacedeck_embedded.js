'use strict';

(function() {
  var isEmbedded = (function() {
    try {
      return window && window.self !== window.top;
    } catch (err) {
      return false;
    }
  })();

  if (!isEmbedded) return;

  var allowedOrigins = (window.ENV && Array.isArray(window.ENV.allowedEmbedOrigins))
    ? window.ENV.allowedEmbedOrigins.slice()
    : [];

  var postMessageTimeoutMs = (window.ENV && window.ENV.postMessageTimeoutMs) || 5000;
  var loginInFlight = false;
  var timeoutId = null;

  window.__spacedeckEmbeddedLoginPending = true;
  window.__spacedeckEmbeddedAuthenticated = false;

  function originAllowed(origin) {
    if (!origin) return false;
    if (origin === window.location.origin) return true;
    return allowedOrigins.indexOf(origin) !== -1;
  }

  function flushEmbeddedQueue() {
    if (!window.__spacedeckEmbeddedLoginQueue || !window.__spacedeckEmbeddedLoginQueue.length) return;
    var queue = window.__spacedeckEmbeddedLoginQueue.slice();
    window.__spacedeckEmbeddedLoginQueue.length = 0;
    queue.forEach(function(fn) {
      try {
        if (typeof fn === "function") fn();
      } catch (err) {
        console.warn("[spacedeck] embedded login queue handler failed", err);
      }
    });
  }

  function markAuthenticated() {
    window.__spacedeckEmbeddedAuthenticated = true;
    window.__spacedeckEmbeddedLoginPending = false;
    flushEmbeddedQueue();
  }

  function releasePending() {
    window.__spacedeckEmbeddedLoginPending = false;
    flushEmbeddedQueue();
  }

  function scheduleTimeout(vueInstance) {
    if (!postMessageTimeoutMs || postMessageTimeoutMs <= 0) return;
    if (timeoutId) window.clearTimeout(timeoutId);
    timeoutId = window.setTimeout(function() {
      if (window.__spacedeckEmbeddedAuthenticated) return;
      releasePending();
      if (vueInstance && typeof vueInstance.load_user === "function") {
        vueInstance.load_user();
      }
    }, postMessageTimeoutMs);
  }

  function deriveName(data) {
    if (!data) return null;
    return (
      data.name ||
      data.fullName ||
      data.preferred_username ||
      (data.user && (data.user.name || data.user.displayName)) ||
      (data.email ? data.email.split("@")[0] : null) ||
      null
    );
  }

  function deriveEmail(data) {
    if (!data) return null;
    return (
      data.email ||
      (data.user && data.user.email) ||
      data.username ||
      data.userEmail ||
      null
    );
  }

  function createSessionFromToken(payload, onSuccess, onError) {
    if (typeof load_resource !== "function") {
      if (onError) onError();
      return;
    }
    load_resource(
      "post",
      "/sessions/keycloak/token",
      payload,
      onSuccess,
      onError
    );
  }

  function loginWithPayload(payload, vueInstance) {
    if (!payload || !payload.accessToken || loginInFlight) return;

    if (timeoutId) window.clearTimeout(timeoutId);

    loginInFlight = true;
    window.__spacedeckEmbeddedLoginPending = true;

    createSessionFromToken(payload, function(resp) {
      loginInFlight = false;
      markAuthenticated();
      if (vueInstance && typeof vueInstance.finalize_login === "function") {
        var sessionToken = resp && resp.session ? resp.session.token : null;
        vueInstance.finalize_login(sessionToken, function() {});
      }
    }, function() {
      loginInFlight = false;
      releasePending();
    });
  }

  function handleForceLogout(vueInstance, data) {
    var nextToken = data && (data.nextToken || data.accessToken || data.access_token || data.token);
    var nextRefreshToken = data && data.refreshToken;
    var nextIdToken = data && (data.idToken || data.id_token);

    window.__spacedeckEmbeddedAuthenticated = false;
    window.__spacedeckEmbeddedLoginPending = false;
    try {
      if (window.sessionStorage) {
        window.sessionStorage.removeItem("sd_session_token");
        window.sessionStorage.removeItem("sd_session_email");
        window.sessionStorage.removeItem("sd_session_name");
        window.sessionStorage.removeItem("sd_session_user_id");
      }
      if (window.localStorage) {
        window.localStorage.removeItem("sd_session_token");
        window.localStorage.removeItem("sd_session_email");
        window.localStorage.removeItem("sd_session_name");
        window.localStorage.removeItem("sd_session_user_id");
      }
    } catch (err) {
      try { console.warn("[spacedeck] Unable to clear embedded session storage", err); } catch (e) {}
    }

    var afterLogout = function() {
      if (nextToken) {
        loginWithPayload({
          accessToken: nextToken,
          refreshToken: nextRefreshToken || null,
          idToken: nextIdToken || null,
          email: deriveEmail(data),
          name: deriveName(data),
          language: data && data.language,
          profile: data && data.profile
        }, vueInstance);
        return;
      }

      window.location.reload();
    };

    if (typeof delete_session === "function") {
      delete_session(afterLogout, afterLogout);
    } else {
      afterLogout();
    }
  }

  function handleMessage(event, vueInstance) {
    if (!originAllowed(event.origin)) return;
    var data = event.data || {};

    if (data.type === "spacedeck-force-logout") {
      handleForceLogout(vueInstance, data);
      return;
    }

    var accessToken = data.accessToken || data.access_token || data.token;
    if (!accessToken) return;

    var payload = {
      accessToken: accessToken,
      refreshToken: data.refreshToken || null,
      language: data.language || null,
      email: deriveEmail(data),
      name: deriveName(data),
      profile: data.profile || null
    };

    if (data.idToken || data.id_token) {
      payload.idToken = data.idToken || data.id_token;
    }

    loginWithPayload(payload, vueInstance);
  }

  window.__spacedeckInitEmbeddedAuth = function(vueInstance) {
    scheduleTimeout(vueInstance);
    window.addEventListener("message", function(event) {
      handleMessage(event, vueInstance);
    }, false);
  };
})();
