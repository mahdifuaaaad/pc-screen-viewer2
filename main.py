import io
import json
import socket
import struct
import threading
import time

from kivy.config import Config
Config.set('input', 'mouse', 'mouse,disable_multitouch')

from kivy.app import App
from kivy.clock import Clock
from kivy.core.image import Image as CoreImage
from kivy.graphics import Color, Line, Rectangle, RoundedRectangle
from kivy.metrics import dp
from kivy.properties import BooleanProperty, DictProperty, ListProperty, NumericProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.image import Image
from kivy.uix.label import Label
from kivy.uix.modalview import ModalView
from kivy.uix.scatter import Scatter
from kivy.uix.screenmanager import FadeTransition, Screen, ScreenManager
from kivy.uix.scrollview import ScrollView
from kivy.uix.slider import Slider
from kivy.uix.stencilview import StencilView
from kivy.uix.textinput import TextInput


class CyberPanel(BoxLayout):
    bg_color = ListProperty([0.08, 0.11, 0.18, 0.95])
    border_color = ListProperty([0.0, 0.92, 1.0, 0.55])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.padding = dp(12)
        self.spacing = dp(8)
        with self.canvas.before:
            self.c_bg = Color(*self.bg_color)
            self.rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(14)])
            self.c_border = Color(*self.border_color)
            self.line = Line(rounded_rectangle=(self.pos[0], self.pos[1], self.size[0], self.size[1], dp(14)), width=1.2)
        self.bind(pos=self._upd, size=self._upd, bg_color=self._upd_c, border_color=self._upd_c)

    def _upd(self, *args):
        self.rect.pos = self.pos
        self.rect.size = self.size
        self.line.rounded_rectangle = (self.pos[0], self.pos[1], self.size[0], self.size[1], dp(14))

    def _upd_c(self, *args):
        self.c_bg.rgba = self.bg_color
        self.c_border.rgba = self.border_color


class GlowButton(Button):
    btn_color = ListProperty([0.0, 0.68, 0.90, 1])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.background_normal = ''
        self.background_down = ''
        self.background_color = [0, 0, 0, 0]
        self.bold = True
        self.color = [1, 1, 1, 1]
        with self.canvas.before:
            self.c_bg = Color(*self.btn_color)
            self.rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(10)])
        self.bind(pos=self._upd, size=self._upd, btn_color=self._upd_c, state=self._on_state)

    def _upd(self, *args):
        self.rect.pos = self.pos
        self.rect.size = self.size

    def _upd_c(self, *args):
        self.c_bg.rgba = self.btn_color

    def _on_state(self, inst, val):
        if val == 'down':
            self.c_bg.rgba = [min(1.0, c + 0.22) for c in self.btn_color[:3]] + [1]
        else:
            self.c_bg.rgba = self.btn_color


class StencilBox( FloatLayout, StencilView):
    pass


class NexusMobileReceiverApp(App):
    # Persistent Session State
    session_locked = BooleanProperty(False)
    link_online = BooleanProperty(False)
    freeze_active = BooleanProperty(False)
    stretch_active = BooleanProperty(False)
    hud_shown = BooleanProperty(True)

    # Target Host
    target_ip = StringProperty("127.0.0.1")
    target_port = NumericProperty(5050)
    target_hostname = StringProperty("PC")

    # Viewer Preferences
    zoom_level = NumericProperty(1.0)
    night_dimmer = NumericProperty(0.0)
    active_preset = StringProperty("BALANCED")
    active_color = StringProperty("RGB")

    # Discovered Hosts { "192.168.1.5:5050": {"ip": ..., "port": ..., "hostname": ...} }
    discovered_hosts = DictProperty({})
    scan_status_text = StringProperty("Radar Active - Searching for PCs on LAN...")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.active_sock = None
        self.sock_lock = threading.Lock()
        self.stop_all = False
        self.is_scanning = False
        self._frames_rcvd = 0
        self._bytes_rcvd = 0
        self.quality_btns = {}
        self.color_btns = {}

    def get_my_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def build(self):
        self.title = "NexusCast Mobile LAN Receiver"
        self.sm = ScreenManager(transition=FadeTransition(duration=0.18))

        self.radar_screen = self._build_radar_screen()
        self.viewer_screen = self._build_viewer_screen()
        self.sm.add_widget(self.radar_screen)
        self.sm.add_widget(self.viewer_screen)

        self.settings_popup = self._build_settings_popup()

        # Start Discovery & Persistent Watchdog Threads
        threading.Thread(target=self.udp_radar_listener, daemon=True).start()
        threading.Thread(target=self.persistent_connection_watchdog, daemon=True).start()
        Clock.schedule_once(lambda dt: self.trigger_active_lan_scan(), 0.4)
        Clock.schedule_interval(self._update_hud_metrics, 1.0)

        return self.sm

    # ----------------- SCREEN 1: DEVICE SCANNER & RADAR -----------------
    def _build_radar_screen(self):
        scr = Screen(name="radar")
        root = BoxLayout(orientation='vertical', padding=dp(14), spacing=dp(10))
        with root.canvas.before:
            Color(0.03, 0.05, 0.09, 1)
            bg = Rectangle(pos=root.pos, size=root.size)
        root.bind(pos=lambda i, v: setattr(bg, 'pos', v), size=lambda i, v: setattr(bg, 'size', v))

        # Top Title Banner
        top_card = CyberPanel(size_hint_y=None, height=dp(80), orientation='horizontal')
        title_col = BoxLayout(orientation='vertical')
        t1 = Label(text="NEXUSCAST // LAN DEVICE SCANNER", font_size='18sp', bold=True,
                   color=[0, 0.95, 1, 1], halign='left', valign='middle')
        t1.bind(size=t1.setter('text_size'))
        self.lbl_scan_state = Label(text=self.scan_status_text, font_size='12sp',
                                    color=[0.4, 1.0, 0.65, 1], halign='left', valign='middle')
        self.lbl_scan_state.bind(size=self.lbl_scan_state.setter('text_size'))
        title_col.add_widget(t1)
        title_col.add_widget(self.lbl_scan_state)

        self.btn_scan = GlowButton(text="SCAN LAN NOW", size_hint=(None, None),
                                   size=(dp(150), dp(46)), btn_color=[0.0, 0.72, 0.52, 1])
        self.btn_scan.bind(on_release=lambda *a: self.trigger_active_lan_scan())
        top_card.add_widget(title_col)
        top_card.add_widget(self.btn_scan)
        root.add_widget(top_card)

        # Discovered PCs List Card (Main Area)
        list_card = CyberPanel(orientation='vertical')
        hdr_row = BoxLayout(size_hint_y=None, height=dp(28))
        lbl_h = Label(text="AVAILABLE PC HOSTS ON NETWORK (TAP TO CONNECT):", font_size='13sp',
                      bold=True, color=[0, 0.92, 1, 1], halign='left')
        lbl_h.bind(size=lbl_h.setter('text_size'))
        hdr_row.add_widget(lbl_h)
        list_card.add_widget(hdr_row)

        scroll = ScrollView()
        self.devices_box = GridLayout(cols=1, spacing=dp(8), size_hint_y=None, padding=dp(4))
        self.devices_box.bind(minimum_height=self.devices_box.setter('height'))
        scroll.add_widget(self.devices_box)
        list_card.add_widget(scroll)
        root.add_widget(list_card)

        # Bottom Manual IP Connect Bar + Settings Button
        bottom_card = CyberPanel(size_hint_y=None, height=dp(66), orientation='horizontal')
        bottom_card.add_widget(Label(text="Direct IP:", size_hint_x=None, width=dp(70), bold=True))
        self.inp_manual_ip = TextInput(text=self.get_my_ip(), multiline=False, font_size='15sp',
                                       size_hint_y=None, height=dp(40), pos_hint={'center_y': 0.5},
                                       background_color=[0.12, 0.17, 0.26, 1], foreground_color=[1, 1, 1, 1])
        bottom_card.add_widget(self.inp_manual_ip)

        btn_direct = GlowButton(text="CONNECT IP", size_hint=(None, None), size=(dp(125), dp(40)),
                                pos_hint={'center_y': 0.5}, btn_color=[0.0, 0.65, 0.85, 1])
        btn_direct.bind(on_release=self.connect_manual_ip)
        bottom_card.add_widget(btn_direct)

        btn_cfg_main = GlowButton(text="SETTINGS", size_hint=(None, None), size=(dp(110), dp(40)),
                                  pos_hint={'center_y': 0.5}, btn_color=[0.22, 0.30, 0.48, 1])
        btn_cfg_main.bind(on_release=lambda *a: self.settings_popup.open())
        bottom_card.add_widget(btn_cfg_main)

        root.add_widget(bottom_card)
        self._refresh_devices_ui()
        scr.add_widget(root)
        return scr

    def _refresh_devices_ui(self, *args):
        self.devices_box.clear_widgets()
        if not self.discovered_hosts:
            empty_lbl = Label(
                text="No PC Host found yet.\n1. Run pc_host.py on your PC.\n2. Tap 'SCAN LAN NOW' above.",
                font_size='14sp', color=[0.65, 0.75, 0.88, 1], halign='center', size_hint_y=None, height=dp(110)
            )
            self.devices_box.add_widget(empty_lbl)
            return

        for key, info in self.discovered_hosts.items():
            row = CyberPanel(size_hint_y=None, height=dp(68), orientation='horizontal',
                             bg_color=[0.11, 0.16, 0.25, 1], border_color=[0.0, 0.95, 0.65, 0.8])
            txt_box = BoxLayout(orientation='vertical')
            l1 = Label(text=f"PC: {info['hostname']}", font_size='16sp', bold=True,
                       color=[1, 1, 1, 1], halign='left', valign='middle')
            l1.bind(size=l1.setter('text_size'))
            l2 = Label(text=f"IP Address: {info['ip']}:{info['port']}  ● READY", font_size='12sp',
                       color=[0.3, 1.0, 0.65, 1], halign='left', valign='middle')
            l2.bind(size=l2.setter('text_size'))
            txt_box.add_widget(l1)
            txt_box.add_widget(l2)

            btn_conn = GlowButton(text="CONNECT & LOCK", size_hint=(None, None),
                                  size=(dp(160), dp(44)), pos_hint={'center_y': 0.5},
                                  btn_color=[0.0, 0.75, 0.48, 1])
            btn_conn.bind(on_release=lambda inst, i=info['ip'], p=info['port'], h=info['hostname']: self.lock_and_connect(i, p, h))
            row.add_widget(txt_box)
            row.add_widget(btn_conn)
            self.devices_box.add_widget(row)

    # ----------------- SCREEN 2: LOCKED LIVE STREAM RECEIVER -----------------
    def _build_viewer_screen(self):
        scr = Screen(name="viewer")
        fl = FloatLayout()
        with fl.canvas.before:
            Color(0.01, 0.01, 0.02, 1)
            bg = Rectangle(pos=fl.pos, size=fl.size)
        fl.bind(pos=lambda i, v: setattr(bg, 'pos', v), size=lambda i, v: setattr(bg, 'size', v))

        # Zoomable & Pan-able Stream Viewport
        self.viewport = StencilBox(size_hint=(1, 1))
        self.scatter = Scatter(do_rotation=False, do_scale=True, do_translation=True,
                               scale_min=1.0, scale_max=3.0, size_hint=(None, None))
        self.stream_img = Image(allow_stretch=True, keep_ratio=True)
        self.scatter.add_widget(self.stream_img)
        self.viewport.add_widget(self.scatter)
        self.viewport.bind(size=self._sync_scatter_size)
        fl.add_widget(self.viewport)

        # Night Dimmer Filter Overlay
        self.dim_layer = FloatLayout(size_hint=(1, 1))
        with self.dim_layer.canvas:
            self.dim_color = Color(0.0, 0.0, 0.0, 0.0)
            self.dim_rect = Rectangle(pos=self.dim_layer.pos, size=self.dim_layer.size)
        self.dim_layer.bind(pos=lambda i, v: setattr(self.dim_rect, 'pos', v),
                            size=lambda i, v: setattr(self.dim_rect, 'size', v))
        fl.add_widget(self.dim_layer)

        # Top Telemetry HUD
        self.top_bar = CyberPanel(size_hint=(0.96, None), height=dp(50),
                                  pos_hint={'center_x': 0.5, 'top': 0.98}, orientation='horizontal')
        self.lbl_conn_state = Label(text="● CONNECTING...", font_size='13sp', bold=True,
                                    color=[0.3, 1.0, 0.65, 1], halign='left', valign='middle')
        self.lbl_conn_state.bind(size=self.lbl_conn_state.setter('text_size'))
        self.lbl_fps_bw = Label(text="0 FPS | 0 KB/s", font_size='13sp', bold=True,
                                color=[0.85, 0.95, 1, 1], size_hint_x=None, width=dp(150))
        self.btn_hide_hud = GlowButton(text="HIDE BAR", size_hint=(None, None), size=(dp(95), dp(32)),
                                       pos_hint={'center_y': 0.5}, btn_color=[0.2, 0.28, 0.42, 1], font_size='11sp')
        self.btn_hide_hud.bind(on_release=self.toggle_hud)

        self.top_bar.add_widget(self.lbl_conn_state)
        self.top_bar.add_widget(self.lbl_fps_bw)
        self.top_bar.add_widget(self.btn_hide_hud)
        fl.add_widget(self.top_bar)

        # Small Corner Button to Restore HUD when hidden
        self.btn_restore_hud = GlowButton(text="SHOW MENU", size_hint=(None, None), size=(dp(105), dp(36)),
                                          pos_hint={'right': 0.98, 'top': 0.98},
                                          btn_color=[0.0, 0.65, 0.85, 0.85], font_size='11sp')
        self.btn_restore_hud.opacity = 0.0
        self.btn_restore_hud.disabled = True
        self.btn_restore_hud.bind(on_release=self.toggle_hud)
        fl.add_widget(self.btn_restore_hud)

        # Bottom Interactive Control Bar (Every button has live feedback)
        self.bot_bar = CyberPanel(size_hint=(0.96, None), height=dp(60),
                                  pos_hint={'center_x': 0.5, 'y': 0.02}, orientation='horizontal')

        self.btn_fit = GlowButton(text="MODE: FIT", font_size='12sp', btn_color=[0.18, 0.32, 0.52, 1])
        self.btn_fit.bind(on_release=self.toggle_fit_stretch)

        self.btn_zoom = GlowButton(text="ZOOM: 1.0x", font_size='12sp', btn_color=[0.18, 0.32, 0.52, 1])
        self.btn_zoom.bind(on_release=self.cycle_zoom)

        self.btn_freeze = GlowButton(text="FREEZE: OFF", font_size='12sp', btn_color=[0.18, 0.32, 0.52, 1])
        self.btn_freeze.bind(on_release=self.toggle_freeze_stream)

        btn_settings = GlowButton(text="SETTINGS", font_size='12sp', btn_color=[0.0, 0.60, 0.82, 1])
        btn_settings.bind(on_release=lambda *a: self.settings_popup.open())

        btn_exit = GlowButton(text="DISCONNECT", font_size='12sp', btn_color=[0.82, 0.16, 0.26, 1])
        btn_exit.bind(on_release=self.unlock_and_disconnect)

        self.bot_bar.add_widget(self.btn_fit)
        self.bot_bar.add_widget(self.btn_zoom)
        self.bot_bar.add_widget(self.btn_freeze)
        self.bot_bar.add_widget(btn_settings)
        self.bot_bar.add_widget(btn_exit)
        fl.add_widget(self.bot_bar)

        scr.add_widget(fl)
        return scr

    def _sync_scatter_size(self, inst, sz):
        self.scatter.size = sz
        self.stream_img.size = sz
        if self.scatter.scale == 1.0:
            self.scatter.pos = (0, 0)

    # ----------------- SETTINGS POPUP (100% WORKING BUTTONS) -----------------
    def _build_settings_popup(self):
        modal = ModalView(size_hint=(0.90, 0.82), background_color=[0, 0, 0, 0.82])
        card = CyberPanel(orientation='vertical', padding=dp(16), spacing=dp(12))

        card.add_widget(Label(text="RECEIVER & STREAM CONTROL SETTINGS", font_size='16sp',
                              bold=True, color=[0, 0.95, 1, 1], size_hint_y=None, height=dp(30)))

        # 1. Remote Stream Quality Preset
        card.add_widget(Label(text="Remote PC Stream Quality (Instant Switch):", font_size='13sp',
                              size_hint_y=None, height=dp(22)))
        q_row = GridLayout(cols=3, spacing=dp(8), size_hint_y=None, height=dp(44))
        for q_name in ["FAST", "BALANCED", "ULTRA"]:
            b = GlowButton(text=q_name)
            b.bind(on_release=lambda inst, q=q_name: self.set_remote_quality(q))
            self.quality_btns[q_name] = b
            q_row.add_widget(b)
        card.add_widget(q_row)

        # 2. Remote Color Filter
        card.add_widget(Label(text="Remote Display Color Mode:", font_size='13sp',
                              size_hint_y=None, height=dp(22)))
        c_row = GridLayout(cols=4, spacing=dp(8), size_hint_y=None, height=dp(44))
        for cm in ["RGB", "GRAY", "CONTRAST", "INVERT"]:
            b = GlowButton(text=cm, font_size='12sp')
            b.bind(on_release=lambda inst, m=cm: self.set_remote_color(m))
            self.color_btns[cm] = b
            c_row.add_widget(b)
        card.add_widget(c_row)

        # 3. Eye-Care Night Dimmer Slider
        self.lbl_dim = Label(text="Phone Night Eye-Care Brightness Dimmer: 0%", font_size='13sp',
                             size_hint_y=None, height=dp(24))
        card.add_widget(self.lbl_dim)
        sl_dim = Slider(min=0.0, max=0.75, value=0.0, step=0.05, size_hint_y=None, height=dp(38))
        sl_dim.bind(value=self._on_dimmer_slide)
        card.add_widget(sl_dim)

        # Spacer
        card.add_widget(BoxLayout())

        btn_done = GlowButton(text="APPLY & CLOSE", size_hint_y=None, height=dp(48),
                              btn_color=[0.0, 0.72, 0.48, 1])
        btn_done.bind(on_release=lambda *a: modal.dismiss())
        card.add_widget(btn_done)

        modal.add_widget(card)
        self.set_remote_quality("BALANCED")
        self.set_remote_color("RGB")
        return modal

    # ----------------- INTERACTIVE BUTTON CALLBACKS -----------------
    def lock_and_connect(self, ip, port, hostname="PC"):
        self.target_ip = ip
        self.target_port = int(port)
        self.target_hostname = hostname
        self.session_locked = True
        self.sm.current = "viewer"

    def connect_manual_ip(self, *args):
        ip = self.inp_manual_ip.text.strip()
        if ip:
            self.lock_and_connect(ip, 5050, ip)

    def unlock_and_disconnect(self, *args):
        self.session_locked = False
        self.link_online = False
        with self.sock_lock:
            if self.active_sock:
                try:
                    self.active_sock.close()
                except Exception:
                    pass
                self.active_sock = None
        self.sm.current = "radar"

    def toggle_fit_stretch(self, *args):
        self.stretch_active = not self.stretch_active
        self.stream_img.keep_ratio = not self.stretch_active
        if self.stretch_active:
            self.btn_fit.text = "MODE: STRETCH"
            self.btn_fit.btn_color = [0.0, 0.70, 0.50, 1]
        else:
            self.btn_fit.text = "MODE: FIT"
            self.btn_fit.btn_color = [0.18, 0.32, 0.52, 1]

    def cycle_zoom(self, *args):
        if self.zoom_level == 1.0:
            self.zoom_level = 1.5
        elif self.zoom_level == 1.5:
            self.zoom_level = 2.2
        else:
            self.zoom_level = 1.0
        self.scatter.scale = self.zoom_level
        if self.zoom_level == 1.0:
            self.scatter.pos = (0, 0)
            self.btn_zoom.btn_color = [0.18, 0.32, 0.52, 1]
        else:
            self.btn_zoom.btn_color = [0.0, 0.70, 0.50, 1]
        self.btn_zoom.text = f"ZOOM: {self.zoom_level}x"

    def toggle_freeze_stream(self, *args):
        self.freeze_active = not self.freeze_active
        if self.freeze_active:
            self.btn_freeze.text = "FREEZE: ON"
            self.btn_freeze.btn_color = [0.88, 0.45, 0.10, 1]
        else:
            self.btn_freeze.text = "FREEZE: OFF"
            self.btn_freeze.btn_color = [0.18, 0.32, 0.52, 1]

    def toggle_hud(self, *args):
        self.hud_shown = not self.hud_shown
        if self.hud_shown:
            self.top_bar.opacity = 1.0
            self.top_bar.disabled = False
            self.bot_bar.opacity = 1.0
            self.bot_bar.disabled = False
            self.btn_restore_hud.opacity = 0.0
            self.btn_restore_hud.disabled = True
        else:
            self.top_bar.opacity = 0.0
            self.top_bar.disabled = True
            self.bot_bar.opacity = 0.0
            self.bot_bar.disabled = True
            self.btn_restore_hud.opacity = 1.0
            self.btn_restore_hud.disabled = False

    def set_remote_quality(self, preset_name):
        self.active_preset = preset_name
        for k, b in self.quality_btns.items():
            b.btn_color = [0.0, 0.72, 0.48, 1] if k == preset_name else [0.18, 0.26, 0.40, 1]
        self.send_cmd({"preset": preset_name})

    def set_remote_color(self, cm):
        self.active_color = cm
        for k, b in self.color_btns.items():
            b.btn_color = [0.0, 0.65, 0.88, 1] if k == cm else [0.18, 0.26, 0.40, 1]
        self.send_cmd({"color": cm})

    def _on_dimmer_slide(self, inst, val):
        self.night_dimmer = float(val)
        self.lbl_dim.text = f"Phone Night Eye-Care Brightness Dimmer: {int(val * 100)}%"
        self.dim_color.rgba = [0.0, 0.0, 0.0, self.night_dimmer]

    def send_cmd(self, data_dict):
        def _task():
            with self.sock_lock:
                s = self.active_sock
            if s:
                try:
                    raw = json.dumps(data_dict).encode('utf-8')
                    s.sendall(struct.pack('>I', len(raw)) + raw)
                except Exception:
                    pass
        threading.Thread(target=_task, daemon=True).start()

    # ----------------- ACTIVE LAN SCANNER + RADAR ENGINE -----------------
    def register_found_host(self, ip, port, hostname):
        key = f"{ip}:{port}"
        self.discovered_hosts[key] = {"ip": ip, "port": int(port), "hostname": hostname}
        self.lbl_scan_state.text = f"Found {len(self.discovered_hosts)} PC Host(s) Ready on LAN!"
        self._refresh_devices_ui()

    def udp_radar_listener(self):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            udp.bind(('', 5051))
        except Exception:
            return
        while not self.stop_all:
            try:
                data, _ = udp.recvfrom(1024)
                info = json.loads(data.decode('utf-8'))
                if info.get("service") == "NEXUSCAST_HOST":
                    ip = info.get("ip", "127.0.0.1")
                    port = info.get("port", 5050)
                    host = info.get("hostname", "PC-Host")
                    Clock.schedule_once(lambda dt, i=ip, p=port, h=host: self.register_found_host(i, p, h), 0)
            except Exception:
                time.sleep(0.5)

    def trigger_active_lan_scan(self):
        if self.is_scanning:
            return
        self.is_scanning = True
        self.btn_scan.text = "SCANNING..."
        self.btn_scan.btn_color = [0.85, 0.50, 0.10, 1]
        self.lbl_scan_state.text = "Actively probing all local Wi-Fi IPs (1-254)..."
        threading.Thread(target=self._active_scan_worker, daemon=True).start()

    def _probe_single_ip(self, ip, port=5050):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.35)
            s.connect((ip, port))
            probe = json.dumps({"type": "SCAN_PROBE"}).encode('utf-8')
            s.sendall(struct.pack('>I', len(probe)) + probe)
            hdr = s.recv(4)
            if hdr:
                ln = struct.unpack('>I', hdr)[0]
                resp = json.loads(s.recv(ln).decode('utf-8'))
                if resp.get("service") == "NEXUSCAST_HOST":
                    h_name = resp.get("hostname", "PC-Host")
                    Clock.schedule_once(lambda dt, i=ip, p=port, h=h_name: self.register_found_host(i, p, h), 0)
            s.close()
        except Exception:
            pass

    def _active_scan_worker(self):
        # 1. Send UDP Broadcast Ping
        try:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            u.sendto(b"NEXUS_SCAN_PING", ('255.255.255.255', 5052))
            u.sendto(b"NEXUS_SCAN_PING", ('127.0.0.1', 5052))
            u.close()
        except Exception:
            pass

        # 2. Probe Localhost first (in case testing on same PC)
        self._probe_single_ip("127.0.0.1", 5050)

        # 3. Fast Parallel Probe of all 254 IPs in current Wi-Fi subnet
        my_ip = self.get_my_ip()
        parts = my_ip.split('.')
        if len(parts) == 4 and my_ip != "127.0.0.1":
            prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."
            threads = []
            for last_octet in range(1, 255):
                cand_ip = f"{prefix}{last_octet}"
                t = threading.Thread(target=self._probe_single_ip, args=(cand_ip, 5050), daemon=True)
                threads.append(t)
                t.start()
                if len(threads) >= 50:
                    for th in threads:
                        th.join()
                    threads.clear()
            for th in threads:
                th.join()

        def _finish(dt):
            self.is_scanning = False
            self.btn_scan.text = "SCAN LAN NOW"
            self.btn_scan.btn_color = [0.0, 0.72, 0.52, 1]
            if self.discovered_hosts:
                self.lbl_scan_state.text = f"Scan Complete: {len(self.discovered_hosts)} PC Host(s) Online!"
            else:
                self.lbl_scan_state.text = "Scan Complete: No PC found. Make sure pc_host.py is running."
        Clock.schedule_once(_finish, 0)

    # ----------------- PERSISTENT STREAM WATCHDOG -----------------
    def _recv_exact(self, sock, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def persistent_connection_watchdog(self):
        while not self.stop_all:
            if not self.session_locked:
                time.sleep(0.15)
                continue

            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.5)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                sock.connect((self.target_ip, int(self.target_port)))

                hello = json.dumps({"type": "STREAM_VIEWER"}).encode('utf-8')
                sock.sendall(struct.pack('>I', len(hello)) + hello)

                with self.sock_lock:
                    self.active_sock = sock
                self.link_online = True

                while self.session_locked and not self.stop_all:
                    hdr = self._recv_exact(sock, 4)
                    if not hdr:
                        break
                    f_len = struct.unpack('>I', hdr)[0]
                    if f_len <= 0 or f_len > 12_000_000:
                        break
                    jpg = self._recv_exact(sock, f_len)
                    if not jpg:
                        break

                    self._frames_rcvd += 1
                    self._bytes_rcvd += (f_len + 4)

                    if not self.freeze_active:
                        Clock.schedule_once(lambda dt, b=jpg: self._draw_frame(b), 0)

            except Exception:
                pass
            finally:
                self.link_online = False
                with self.sock_lock:
                    if self.active_sock == sock:
                        self.active_sock = None
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
                if self.session_locked:
                    time.sleep(0.8)

    def _draw_frame(self, jpg_bytes):
        try:
            cim = CoreImage(io.BytesIO(jpg_bytes), ext='jpg')
            self.stream_img.texture = cim.texture
        except Exception:
            pass

    def _update_hud_metrics(self, dt):
        fps = self._frames_rcvd
        kbps = int(self._bytes_rcvd / 1024)
        self._frames_rcvd = 0
        self._bytes_rcvd = 0

        if self.session_locked:
            if self.link_online:
                self.lbl_conn_state.text = f"● CONNECTED TO {self.target_hostname} ({self.target_ip})"
                self.lbl_conn_state.color = [0.25, 1.0, 0.60, 1]
            else:
                self.lbl_conn_state.text = f"● RECONNECTING TO {self.target_ip} (LOCKED)..."
                self.lbl_conn_state.color = [1.0, 0.72, 0.15, 1]
            self.lbl_fps_bw.text = f"{fps} FPS | {kbps} KB/s"

    def on_stop(self):
        self.stop_all = True
        self.session_locked = False


if __name__ == '__main__':
    NexusMobileReceiverApp().run()