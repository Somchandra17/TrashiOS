"""
Runtime instrumentation layer for TrashiOS — the `Drozer` equivalent.

Hybrid design:
  • objection (non-interactive)  — high-level introspection: keychain dump,
    plist/nsuserdefaults/sqlite, cookies, pasteboard, binary info, frameworks,
    SSL-pinning / jailbreak-detection bypass. objection tracks Frida/iOS API
    drift so the phases don't have to.
  • raw Frida bindings           — spawn/attach and custom JS agents (memory
    dump, openURL hooks). Used where objection is too coarse.

objection is driven non-interactively by writing a small startup-script that
ends in `exit` and running `objection -g <bundle> explore -q -S <script>`.
Output is captured and REPL noise stripped, mirroring TrashDroid's
`Drozer.run_module` / `_strip_drozer_noise` pattern. Results are returned as
`RuntimeResult`, which has the same shape as `DrozerResult` so the report's
command-evidence extraction keeps working.

Note: objection attaches to the *running* app, so phases should launch the
target (IOSDevice.launch_app) before calling introspection helpers.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()


def _load_objc_bridge() -> str:
    """Frida 17 removed the built-in `ObjC` global from raw scripts. frida-tools ships the
    compiled bridge; prepend it (+ alias) so our ObjC agents work on Frida 16 and 17 alike."""
    try:
        import frida_tools
        p = Path(frida_tools.__file__).parent / "bridges" / "objc.js"
        if p.exists():
            return p.read_text(encoding="utf-8") + "\nvar ObjC = bridge;\n"
    except Exception:
        pass
    return ""  # Frida <17 has ObjC built-in; agents run fine without the prepend


_OBJC_BRIDGE = _load_objc_bridge()


def _with_objc(agent_src: str) -> str:
    """Prepend the ObjC bridge to an agent that uses the `ObjC` global."""
    return _OBJC_BRIDGE + agent_src


# objection prompt / banner lines to strip from captured output.
_PROMPT_RE = re.compile(r"^\S+ on \(.*\) \[usb\] # ", re.MULTILINE)
_NOISE_RE = re.compile(
    r"^(Using USB device|Agent injected|Resuming|\(agent\)|Checking|"
    r"Spawning|Spawned|Restarting|Job:|\[tab\]|exit\s*$)",
    re.IGNORECASE,
)
_ERROR_RE = re.compile(
    r"(Traceback \(most recent call last\)|Failed to|Unable to|"
    r"could not be found|process .* not found|frida\.\w*Error|"
    r"NeedsBridgeSessionError|No such file)",
    re.IGNORECASE,
)


def _strip_objection_noise(text: str) -> str:
    text = _PROMPT_RE.sub("", text)
    kept = [ln for ln in text.splitlines() if ln.strip() and not _NOISE_RE.match(ln.strip())]
    return "\n".join(kept).strip()


@dataclass
class RuntimeResult:
    module: str
    args: str
    stdout: str
    stderr: str
    success: bool
    raw_stdout: str = ""


class FridaBridge:
    def __init__(self, device, bundle_id: str):
        self.device = device
        self.bundle_id = bundle_id
        self._objection = shutil.which("objection")

    # ── connection (mirror Drozer.setup_port_forward + verify_connection) ──

    def verify_connection(self) -> bool:
        try:
            r = subprocess.run(["frida-ps", "-U"], capture_output=True, text=True, timeout=15)
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def ensure_server(self) -> bool:
        """Ensure frida-server is reachable; try to start it over SSH if not."""
        if self.verify_connection():
            return True
        # Best-effort start over SSH (palera1n usually runs it as a daemon already).
        path = self.device.shell_output("which frida-server 2>/dev/null || echo /usr/sbin/frida-server")
        if path:
            self.device.shell(f"nohup {path} >/dev/null 2>&1 &")
            import time
            time.sleep(2)
        return self.verify_connection()

    # ── objection driver ─────────────────────────────────────────

    def _objection_run(self, command: str, timeout: int = 90) -> RuntimeResult:
        if not self._objection:
            return RuntimeResult("objection", command, "", "objection not found in PATH", False)

        # objection REPL commands go via -s/--startup-command (repeatable, ends with 'exit' to quit).
        # NB: -S/--startup-script is a Frida *JavaScript* file, not REPL commands.
        argv = ["objection", "-g", self.bundle_id, "explore", "-q", "-s", command, "-s", "exit"]
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return RuntimeResult("objection", command, "", f"timed out after {timeout}s", False)
        raw = r.stdout or ""
        clean = _strip_objection_noise(raw)
        had_error = bool(_ERROR_RE.search(raw + " " + (r.stderr or "")))
        success = (r.returncode == 0) and not had_error and bool(clean)
        return RuntimeResult("objection", command, clean, (r.stderr or "").strip(), success, raw)

    # ── objection-backed introspection (the Drozer-module analogues) ──

    _KEYCHAIN_JS = """
rpc.exports = {
  keychain: function () {
    if (!ObjC.available) return { error: 'ObjC unavailable' };
    function cptr(n) { var p = Module.findGlobalExportByName(n); return p ? p.readPointer() : null; }
    function cobj(n) { var p = cptr(n); return p ? new ObjC.Object(p) : null; }
    var addr = Module.findGlobalExportByName('SecItemCopyMatching');
    if (!addr) return { error: 'SecItemCopyMatching not found' };
    var Sec = new NativeFunction(addr, 'int', ['pointer', 'pointer']);
    var kCls = cobj('kSecClass'), kRA = cobj('kSecReturnAttributes'), kRD = cobj('kSecReturnData'),
        kML = cobj('kSecMatchLimit'), kAll = cobj('kSecMatchLimitAll');
    if (!kCls || !kRA || !kML || !kAll) return { error: 'kSec constants unavailable' };
    var T = ObjC.classes.NSNumber.numberWithBool_(1);
    var classes = ['kSecClassGenericPassword', 'kSecClassInternetPassword', 'kSecClassKey',
                   'kSecClassCertificate', 'kSecClassIdentity'];
    var out = [];
    classes.forEach(function (cn) {
      var c = cobj(cn); if (!c) return;
      var q = ObjC.classes.NSMutableDictionary.dictionary();
      q.setObject_forKey_(c, kCls);
      q.setObject_forKey_(T, kRA);
      if (kRD) q.setObject_forKey_(T, kRD);
      q.setObject_forKey_(kAll, kML);
      var rp = Memory.alloc(Process.pointerSize);
      if (Sec(q, rp) !== 0) return;  // errSecItemNotFound etc.
      var res = new ObjC.Object(rp.readPointer());
      var items = [];
      if (res.isKindOfClass_(ObjC.classes.NSArray)) {
        for (var i = 0; i < res.count(); i++) items.push(res.objectAtIndex_(i));
      } else { items.push(res); }
      items.forEach(function (it) {
        function g(k) { try { var v = it.objectForKey_(k); return v ? v.toString() : null; } catch (e) { return null; } }
        var data = null;
        try {
          var d = it.objectForKey_('v_Data');
          if (d) { var s = ObjC.classes.NSString.alloc().initWithData_encoding_(d, 4); data = s ? s.toString() : ('<binary ' + d.length() + ' bytes>'); }
        } catch (e) {}
        out.push({ cls: cn.replace('kSecClass', ''), account: g('acct'), service: g('svce'),
                   agrp: g('agrp'), accessible: g('pdmn'), data: data });
      });
    });
    return { items: out };
  }
};
"""

    def keychain_dump(self):
        """Dump keychain items via a raw Frida agent (objection-free; works on Frida 17).
        Returns (items, error_message). Each item: {cls, account, service, agrp, accessible, data}."""
        try:
            import frida, time
        except Exception as e:
            return [], f"frida python binding unavailable: {e}"
        try:
            dev = frida.get_usb_device(timeout=5)
        except Exception as e:
            return [], f"no USB device: {e}"
        pid = self.device.get_pid(self.bundle_id)
        try:
            if not pid:
                pid = dev.spawn([self.bundle_id]); dev.resume(pid); time.sleep(4)
            session = dev.attach(int(pid))
        except Exception as e:
            return [], f"attach to {self.bundle_id} refused ({e}) — likely anti-debug / managed-app (MAM) protection"
        try:
            script = session.create_script(_with_objc(self._KEYCHAIN_JS))
            script.load()
            exports = getattr(script, "exports_sync", None) or script.exports
            res = exports.keychain()
            try:
                session.detach()
            except Exception:
                pass
            if isinstance(res, dict) and res.get("error"):
                return [], res["error"]
            return (res.get("items", []) if isinstance(res, dict) else []), ""
        except Exception as e:
            return [], f"keychain agent error: {e}"

    def nsuserdefaults(self) -> RuntimeResult:
        return self._objection_run("ios nsuserdefaults get")

    def plist_cat(self, path: str) -> RuntimeResult:
        return self._objection_run(f"ios plist cat '{path}'")

    def sqlite_connect(self, path: str) -> RuntimeResult:
        return self._objection_run(f"ios sqlite connect '{path}'", timeout=120)

    def cookies(self) -> RuntimeResult:
        return self._objection_run("ios cookies get")

    def info_binary(self) -> RuntimeResult:
        return self._objection_run("ios info binary")

    def list_frameworks(self) -> RuntimeResult:
        return self._objection_run("ios bundles list_frameworks")

    def env(self) -> dict:
        """objection `env` -> {'BundlePath':..., 'DataDirectory':...} (feeds container resolver)."""
        res = self._objection_run("env")
        out: dict[str, str] = {}
        for line in res.stdout.splitlines():
            if "  " in line.strip():
                parts = re.split(r"\s{2,}", line.strip(), maxsplit=1)
                if len(parts) == 2:
                    out[parts[0].strip()] = parts[1].strip()
        return out

    def disable_sslpinning(self) -> RuntimeResult:
        return self._objection_run("ios sslpinning disable", timeout=60)

    def disable_jailbreak_detect(self) -> RuntimeResult:
        return self._objection_run("ios jailbreak disable", timeout=60)

    # ── raw Frida (spawn / custom agents — memory dump, hooks) ───

    _OPENURL_JS = """
rpc.exports = {
  openurl: function (u) {
    if (!ObjC.available) return 'no-objc';
    var app = ObjC.classes.UIApplication.sharedApplication();
    var url = ObjC.classes.NSURL.URLWithString_(u);
    ObjC.schedule(ObjC.mainQueue, function () {
      try {
        if (app.respondsToSelector_(ObjC.selector('openURL:options:completionHandler:'))) {
          app.openURL_options_completionHandler_(url, ObjC.classes.NSDictionary.dictionary(), NULL);
        } else {
          app.openURL_(url);
        }
      } catch (e) {}
    });
    return 'ok';
  }
};
"""

    def open_url(self, url: str) -> RuntimeResult:
        """Fire a URL into the app via Frida (UIApplication openURL:) — the
        jailbreak-tool-independent alternative to `uiopen`. The app must be running."""
        try:
            import frida
            import time
            dev = frida.get_usb_device(timeout=5)
            pid = self.device.get_pid(self.bundle_id)
            if not pid:
                pid = dev.spawn([self.bundle_id])
                dev.resume(pid)
                time.sleep(2)
            session = dev.attach(int(pid))
            script = session.create_script(_with_objc(self._OPENURL_JS))
            script.load()
            rv = script.exports_sync.openurl(url)
            time.sleep(1.2)  # let the main-queue dispatch run before detaching
            try:
                session.detach()
            except Exception:
                pass
            return RuntimeResult("frida", f"open_url:{url}", str(rv), "", rv == "ok")
        except Exception as e:
            return RuntimeResult("frida", f"open_url:{url}", "", str(e), False)

    def open_urls(self, urls: list[str], settle: float = 1.0, on_fired=None) -> dict[str, bool]:
        """Fire many URLs in a SINGLE Frida session (one attach for all — much faster
        and more reliable than attaching per URL). `on_fired(url, ok)` is called after
        each fire (e.g. to screenshot the resulting state)."""
        results: dict[str, bool] = {}
        try:
            import frida, time
            dev = frida.get_usb_device(timeout=5)
            pid = self.device.get_pid(self.bundle_id)
            if not pid:
                pid = dev.spawn([self.bundle_id]); dev.resume(pid); time.sleep(3)
            session = dev.attach(int(pid))
            script = session.create_script(_with_objc(self._OPENURL_JS))
            script.load()
            exports = getattr(script, "exports_sync", None) or script.exports
            for u in urls:
                ok = False
                try:
                    ok = exports.openurl(u) == "ok"
                except Exception:
                    ok = False
                results[u] = ok
                time.sleep(settle)
                if on_fired:
                    try:
                        on_fired(u, ok)
                    except Exception:
                        pass
            try:
                session.detach()
            except Exception:
                pass
        except Exception:
            for u in urls:
                results.setdefault(u, False)
        return results

    def spawn(self) -> Optional[int]:
        try:
            import frida
            dev = frida.get_usb_device(timeout=5)
            pid = dev.spawn([self.bundle_id])
            dev.resume(pid)
            return pid
        except Exception as e:
            console.print(f"[yellow]Frida spawn failed: {e}[/yellow]")
            return None

    def run_script(self, js: str, rpc_export: str, *args, attach_pid: Optional[int] = None) -> RuntimeResult:
        """Load a custom Frida JS agent and call one of its rpc.exports (memory phase)."""
        try:
            import frida
            dev = frida.get_usb_device(timeout=5)
            pid = attach_pid or self.device.get_pid(self.bundle_id)
            if not pid:
                pid = dev.spawn([self.bundle_id]); dev.resume(pid)
            session = dev.attach(int(pid))
            script = session.create_script(js)
            holder = {"out": None, "err": None}

            def on_message(message, data):
                if message.get("type") == "error":
                    holder["err"] = message.get("description")
            script.on("message", on_message)
            script.load()
            result = getattr(script.exports_sync, rpc_export)(*args)
            holder["out"] = result
            try:
                session.detach()
            except Exception:
                pass
            return RuntimeResult("frida", rpc_export, str(holder["out"]) if holder["out"] is not None else "",
                                 holder["err"] or "", holder["err"] is None)
        except Exception as e:
            return RuntimeResult("frida", rpc_export, "", str(e), False)

    # ── memory dump (the Memory phase) ───────────────────────────

    _MEMDUMP_JS = """
rpc.exports = {
  ranges: function (prot) {
    return Process.enumerateRanges(prot).map(function (r) { return [r.base.toString(), r.size]; });
  },
  read: function (base, size) {
    try { return ptr(base).readByteArray(size); } catch (e) { return null; }  // Frida 17: NativePointer method
  }
};
"""

    def dump_memory(self, out_path: str, max_mb: int = 256, per_range_mb: int = 16) -> RuntimeResult:
        """Dump rw- process memory ranges to a file via Frida (the fridump equivalent).

        Captures the real failure reason (attach refused, script destroyed by an
        anti-tamper/MAM app, no readable ranges) instead of a generic 'empty'.
        """
        try:
            import frida, time
        except Exception as e:
            return RuntimeResult("frida", "dump_memory", "", f"frida python binding unavailable: {e}", False)

        try:
            dev = frida.get_usb_device(timeout=5)
        except Exception as e:
            return RuntimeResult("frida", "dump_memory", "", f"no USB device: {e}", False)

        pid = self.device.get_pid(self.bundle_id)
        if not pid:
            try:
                pid = dev.spawn([self.bundle_id]); dev.resume(pid); time.sleep(3)
            except Exception as e:
                return RuntimeResult("frida", "dump_memory", "", f"spawn failed: {e}", False)
        try:
            session = dev.attach(int(pid))
        except Exception as e:
            return RuntimeResult("frida", "dump_memory", "",
                                 f"attach to pid {pid} refused ({e}) — likely anti-debug / managed-app (MAM) protection",
                                 False)

        agent_errors: list[str] = []
        try:
            script = session.create_script(self._MEMDUMP_JS)
            script.on("message", lambda m, d: agent_errors.append(m.get("description", "")) if m.get("type") == "error" else None)
            script.load()
            exports = getattr(script, "exports_sync", None) or script.exports
            ranges = exports.ranges("rw-")
            total = 0; written = 0; first_err = None
            cap = max_mb * 1024 * 1024
            per_cap = per_range_mb * 1024 * 1024
            with open(out_path, "wb") as fh:
                for base, size in ranges:
                    if total >= cap:
                        break
                    size = min(int(size), per_cap, cap - total)
                    if size <= 0:
                        continue
                    try:
                        data = exports.read(base, size)
                    except Exception as e:
                        first_err = first_err or str(e)
                        continue
                    if data:
                        fh.write(data); total += len(data); written += 1
            try:
                session.detach()
            except Exception:
                pass
            if total == 0:
                reason = first_err or (agent_errors[0] if agent_errors else f"no readable rw- ranges ({len(ranges)} seen)")
                return RuntimeResult("frida", "dump_memory", "", reason, False)
            return RuntimeResult("frida", "dump_memory",
                                 f"{total} bytes from {written} ranges -> {out_path}", "", True)
        except Exception as e:
            return RuntimeResult("frida", "dump_memory", "",
                                 f"script error ({e}) — process may have detached (anti-tamper)", False)

    # ── pasteboard monitor (the Pasteboard phase) ────────────────

    _PASTEBOARD_JS = """
rpc.exports = { start: function () {
  if (!ObjC.available) return false;
  var UIPasteboard = ObjC.classes.UIPasteboard;
  var last = null;
  setInterval(function () {
    try {
      var s = UIPasteboard.generalPasteboard().string();
      var v = s ? s.toString() : null;
      if (v && v !== last) { last = v; send({pb: v}); }
    } catch (e) {}
  }, 1000);
  return true;
} };
"""

    def pasteboard_monitor(self, seconds: int = 15) -> RuntimeResult:
        """Monitor the general (system) pasteboard for `seconds` and return distinct values seen."""
        try:
            import frida, time
            dev = frida.get_usb_device(timeout=5)
            pid = self.device.get_pid(self.bundle_id)
            if not pid:
                pid = dev.spawn([self.bundle_id]); dev.resume(pid); time.sleep(3)
            session = dev.attach(int(pid))
            script = session.create_script(_with_objc(self._PASTEBOARD_JS))
            seen: list[str] = []

            def on_message(message, data):
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if isinstance(payload, dict) and "pb" in payload:
                        seen.append(payload["pb"])
            script.on("message", on_message)
            script.load()
            script.exports_sync.start()
            time.sleep(seconds)
            try:
                session.detach()
            except Exception:
                pass
            out = "\n".join(f"- {v}" for v in seen)
            return RuntimeResult("frida", "pasteboard_monitor", out, "", True, out)
        except Exception as e:
            return RuntimeResult("frida", "pasteboard_monitor", "", str(e), False)

    # ── screenshot (fallback when idevicescreenshot's DDI isn't available) ──

    _SCREENSHOT_JS = """
rpc.exports = {
  shot: function () {
    return new Promise(function (resolve) {
      if (!ObjC.available) { resolve('no-objc'); return; }
      function fn(name, ret, args) {
        var p = null;
        try {
          if (typeof Module.findGlobalExportByName === 'function') p = Module.findGlobalExportByName(name);
          else if (typeof Module.findExportByName === 'function') p = Module.findExportByName(null, name);
        } catch (e) { p = null; }
        if (!p) {
          try { var m = Process.findModuleByName('UIKitCore'); if (m) p = m.findExportByName(name); } catch (e) {}
        }
        return p ? new NativeFunction(p, ret, args) : null;
      }
      // NB: Frida 17's NativeFunction rejects the 'bool' type ("expected an integer"); use 'int'.
      var Begin = fn('UIGraphicsBeginImageContextWithOptions', 'void', [['double','double'],'int','double']);
      var GetCtx = fn('UIGraphicsGetCurrentContext', 'pointer', []);
      var GetImg = fn('UIGraphicsGetImageFromCurrentImageContext', 'pointer', []);
      var End = fn('UIGraphicsEndImageContext', 'void', []);
      var PNG = fn('UIImagePNGRepresentation', 'pointer', ['pointer']);
      if (!Begin || !GetCtx || !GetImg || !End || !PNG) { resolve('no-uikit-fns'); return; }
      function sizeOf(r) {
        try { if (Array.isArray(r)) { if (Array.isArray(r[1])) return [r[1][0], r[1][1]]; return [r[2], r[3]]; } } catch (e) {}
        try { return [r.size.width, r.size.height]; } catch (e) {}
        return null;
      }
      ObjC.schedule(ObjC.mainQueue, function () {
        try {
          var app = ObjC.classes.UIApplication.sharedApplication();
          var screen = ObjC.classes.UIScreen.mainScreen();
          var scale = screen.scale();
          var sz = sizeOf(screen.bounds()) || [414, 896];
          Begin([sz[0] || 414, sz[1] || 896], 0, scale);  // opaque=0 (false) as int
          var ctx = GetCtx();
          var windows = app.windows();
          for (var i = 0; i < windows.count(); i++) {
            try { windows.objectAtIndex_(i).layer().renderInContext_(ctx); } catch (e) {}
          }
          var img = GetImg();
          End();
          if (img.isNull()) { resolve('no-image'); return; }
          var data = new ObjC.Object(PNG(img));
          if (data.handle.isNull()) { resolve('no-png'); return; }
          var len = data.length();
          len = (len && len.valueOf) ? len.valueOf() : len;
          // Frida 17 removed Memory.readByteArray — use the NativePointer method.
          send({ png: true, len: len }, data.bytes().readByteArray(len));
          resolve('ok');
        } catch (e) { resolve('err:' + e); }
      });
    });
  }
};
"""

    def screenshot(self, out_path: str) -> bool:
        """Render the running app's windows to a PNG via Frida (no Developer Disk Image needed).
        Captures the target app's screen — sufficient for the phases that screenshot."""
        try:
            import frida, time
        except Exception:
            return False
        pid = self.device.get_pid(self.bundle_id)
        if not pid:
            return False
        try:
            dev = frida.get_usb_device(timeout=5)
            session = dev.attach(int(pid))
        except Exception:
            return False
        holder = {"ok": False}
        try:
            script = session.create_script(_with_objc(self._SCREENSHOT_JS))

            def on_message(message, data):
                if (message.get("type") == "send" and isinstance(message.get("payload"), dict)
                        and message["payload"].get("png") and data):
                    try:
                        with open(out_path, "wb") as fh:
                            fh.write(data)
                        holder["ok"] = True
                    except OSError:
                        pass
            script.on("message", on_message)
            script.load()
            exports = getattr(script, "exports_sync", None) or script.exports
            exports.shot()
            time.sleep(0.7)  # let send() deliver the bytes before detaching
        except Exception:
            pass
        finally:
            try:
                session.detach()
            except Exception:
                pass
        return holder["ok"] and Path(out_path).exists() and Path(out_path).stat().st_size > 100
