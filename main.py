# -*- coding: utf-8 -*-
from pathlib import Path
import sqlite3, hashlib, hmac, secrets
from kivy.app import App
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.core.window import Window
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.graphics import Color, RoundedRectangle
from biographies_seed import BIOGRAPHIES
try:
    import arabic_reshaper
    from bidi.algorithm import get_display
    def fa(s): return get_display(arabic_reshaper.reshape(str(s)))
except Exception:
    def fa(s): return str(s)

BG=(0.955,0.975,0.98,1); WHITE=(1,1,1,1); TEAL=(0.10,0.48,0.53,1); DARK=(0.12,0.20,0.24,1); MUTED=(0.38,0.48,0.52,1); PALE=(0.88,0.94,0.95,1); GOLD=(0.91,0.72,0.39,1)
def connect():
    app=App.get_running_app()
    db_path=(Path(app.user_data_dir)/'iranian_might.db') if app else Path('iranian_might.db')
    db_path.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(str(db_path)); c.row_factory=sqlite3.Row; return c

def init_db():
    with connect() as c:
        c.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,salt TEXT NOT NULL)')
        c.execute('''CREATE TABLE IF NOT EXISTS biographies(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE NOT NULL,category TEXT,description TEXT,birth_date TEXT,birth_place TEXT,death_date TEXT,role TEXT,full_bio TEXT,image TEXT)''')
        c.execute('CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,content TEXT NOT NULL)')
        count=c.execute('SELECT COUNT(*) n FROM biographies').fetchone()['n']
        if count==0:
            for p in BIOGRAPHIES:
                c.execute('''INSERT OR IGNORE INTO biographies(name,category,description,birth_date,birth_place,death_date,role,full_bio,image) VALUES(?,?,?,?,?,?,?,?,?)''',(p.get('name',''),p.get('category',''),p.get('description',''),p.get('birth_date',''),p.get('birth_place',''),p.get('death_date',''),p.get('role',''),p.get('full_bio',''),p.get('image','')))

def hashpw(p,s): return hashlib.pbkdf2_hmac('sha256',p.encode(),s.encode(),200000).hex()
def register(u,p):
    u=u.strip()
    if len(u)<3 or len(p)<8: return False,'نام کاربری حداقل ۳ و رمز حداقل ۸ نویسه باشد.'
    salt=secrets.token_hex(16)
    try:
        with connect() as c: c.execute('INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)',(u,hashpw(p,salt),salt))
        return True,'حساب ساخته شد.'
    except sqlite3.IntegrityError: return False,'این نام کاربری قبلاً ثبت شده است.'
def login(u,p):
    with connect() as c: row=c.execute('SELECT password_hash,salt FROM users WHERE username=?',(u.strip(),)).fetchone()
    return bool(row and hmac.compare_digest(row['password_hash'],hashpw(p,row['salt'])))
def change_pw(u,old,new):
    if len(new)<8:return False,'رمز جدید باید حداقل ۸ نویسه باشد.'
    with connect() as c:
        r=c.execute('SELECT password_hash,salt FROM users WHERE username=?',(u,)).fetchone()
        if not r or not hmac.compare_digest(r['password_hash'],hashpw(old,r['salt'])):return False,'رمز فعلی صحیح نیست.'
        s=secrets.token_hex(16); c.execute('UPDATE users SET password_hash=?,salt=? WHERE username=?',(hashpw(new,s),s,u))
    return True,'رمز عبور تغییر کرد.'

class Card(BoxLayout):
    def __init__(self, **kw):
        super().__init__(**kw); self.padding=dp(14); self.spacing=dp(8)
        with self.canvas.before:
            Color(*WHITE); self.bg=RoundedRectangle(pos=self.pos,size=self.size,radius=[dp(16)])
        self.bind(pos=self._sync,size=self._sync)
    def _sync(self,*_): self.bg.pos=self.pos; self.bg.size=self.size

def label(text,size=16,color=DARK,bold=False,halign='right',height=None):
    w=Label(text=fa(text),font_size=dp(size),color=color,bold=bold,halign=halign,valign='middle',size_hint_y=None,height=dp(height or max(36,size*2.2)),text_size=(Window.width-dp(48),None))
    return w

def btn(text,fn=None,primary=False):
    b=Button(text=fa(text),size_hint_y=None,height=dp(48),background_normal='',background_color=TEAL if primary else PALE,color=WHITE if primary else DARK,font_size=dp(15),bold=True)
    if fn:b.bind(on_release=lambda *_:fn())
    return b

def field(hint,password=False):
    return TextInput(hint_text=fa(hint),password=password,multiline=False,size_hint_y=None,height=dp(48),padding=[dp(12),dp(12)],font_size=dp(16),background_normal='',background_active='',background_color=WHITE,foreground_color=DARK,cursor_color=TEAL)

class Base(Screen):
    def shell(self,title,back=True):
        root=BoxLayout(orientation='vertical',padding=dp(16),spacing=dp(10))
        top=BoxLayout(size_hint_y=None,height=dp(48),spacing=dp(8))
        if back: top.add_widget(btn('بازگشت',lambda:self.app.go('dashboard')))
        top.add_widget(label(title,20,TEAL,True))
        root.add_widget(top); self.body=BoxLayout(orientation='vertical',spacing=dp(10)); root.add_widget(self.body); self.clear_widgets(); self.add_widget(root)
    @property
    def app(self): return App.get_running_app()
    def scroller(self, parent=None):
        sv=ScrollView(); box=BoxLayout(orientation='vertical',size_hint_y=None,spacing=dp(10),padding=[0,dp(4)]); box.bind(minimum_height=box.setter('height')); sv.add_widget(box); (parent or self.body).add_widget(sv); return box
    def msg(self,title,message): Popup(title=fa(title),content=label(message,15),size_hint=(.88,.32)).open()

class LoginScreen(Base):
    def on_pre_enter(self):
        self.shell('ورود به IRANIAN MIGHT',False)
        self.body.add_widget(label('به فضای دانش و زندگی‌نامه‌ها خوش آمدید',18,TEAL,True,height=60))
        self.u=field('نام کاربری'); self.p=field('رمز عبور',True); self.body.add_widget(self.u); self.body.add_widget(self.p)
        self.body.add_widget(btn('ورود',self.do_login,True)); self.body.add_widget(btn('ساخت حساب جدید',self.do_register)); self.body.add_widget(label('نسخه اندروید • بدون دستیار هوش مصنوعی',12,MUTED))
    def do_login(self):
        if login(self.u.text,self.p.text): self.app.username=self.u.text.strip(); self.app.go('dashboard')
        else:self.msg('ورود ناموفق','نام کاربری یا رمز عبور اشتباه است.')
    def do_register(self):
        ok,m=register(self.u.text,self.p.text); self.msg('ثبت‌نام',m)
        if ok:self.app.username=self.u.text.strip(); self.app.go('dashboard')

class Dashboard(Base):
    def on_pre_enter(self):
        self.shell('IRANIAN MIGHT',False)
        self.body.add_widget(label('سلام، '+self.app.username,22,TEAL,True,height=55))
        self.body.add_widget(label('یک محیط ساده برای مطالعه، ثبت یادداشت و مدیریت حساب',14,MUTED))
        for t,s,fn in [('دانشنامه زندگی‌نامه‌ها','جست‌وجو و مطالعه شخصیت‌ها',lambda:self.app.go('bios')),('دفتر یادداشت‌ها','ثبت، مشاهده و حذف یادداشت‌ها',lambda:self.app.go('notes')),('تنظیمات حساب','تغییر رمز عبور',lambda:self.app.go('settings'))]:
            c=Card(orientation='vertical',size_hint_y=None,height=dp(105)); c.add_widget(label(t,18,TEAL,True)); c.add_widget(label(s,13,MUTED)); c.add_widget(btn('ورود به بخش',fn,True)); self.body.add_widget(c)
        self.body.add_widget(btn('خروج از حساب',lambda:self.app.go('login')))

class Bios(Base):
    def on_pre_enter(self):
        self.shell('دانشنامه زندگی‌نامه‌ها'); self.search=field('جست‌وجو بر اساس نام یا دسته'); self.search.bind(text=lambda *_:self.render()); self.body.add_widget(self.search); self.listbox=self.scroller(); self.render()
    def render(self):
        if not hasattr(self,'listbox'):return
        self.listbox.clear_widgets()
        q=self.search.text.strip()
        with connect() as c: rows=c.execute('SELECT * FROM biographies WHERE name LIKE ? OR category LIKE ? ORDER BY name',('%'+q+'%','%'+q+'%')).fetchall()
        for r in rows:
            card=Card(orientation='vertical',size_hint_y=None,height=dp(112)); card.add_widget(label(r['name'],17,TEAL,True)); card.add_widget(label(r['role'] or r['category'] or '',13,MUTED)); card.add_widget(btn('مشاهده زندگی‌نامه',lambda row=dict(r):self.detail(row))); self.listbox.add_widget(card)
    def detail(self,p):
        box=BoxLayout(orientation='vertical',padding=dp(14),spacing=dp(8)); sv=ScrollView(); content=BoxLayout(orientation='vertical',size_hint_y=None,spacing=dp(8)); content.bind(minimum_height=content.setter('height')); sv.add_widget(content)
        content.add_widget(label(p['name'],20,TEAL,True));
        for k,t in [('role','سمت'),('category','دسته‌بندی'),('birth_date','سال تولد'),('birth_place','محل تولد'),('death_date','سال درگذشت')]:
            if p.get(k):content.add_widget(label(t+': '+p[k],14,MUTED))
        content.add_widget(label(p.get('full_bio') or p.get('description') or 'اطلاعاتی ثبت نشده است.',15,DARK,height=160)); box.add_widget(sv); box.add_widget(btn('بستن',lambda:pop.dismiss(),True)); pop=Popup(title=fa('زندگی‌نامه'),content=box,size_hint=(.94,.82)); pop.open()

class Notes(Base):
    def on_pre_enter(self):
        self.shell('دفتر یادداشت‌ها'); self.editor=TextInput(hint_text=fa('یادداشت جدید...'),multiline=True,size_hint_y=None,height=dp(110),font_size=dp(16),background_color=WHITE,foreground_color=DARK); self.body.add_widget(self.editor); self.body.add_widget(btn('ذخیره یادداشت',self.save,True)); self.listbox=self.scroller(); self.render()
    def save(self):
        v=self.editor.text.strip()
        if not v:return
        with connect() as c:c.execute('INSERT INTO notes(username,content) VALUES(?,?)',(self.app.username,v))
        self.editor.text=''; self.render()
    def render(self):
        self.listbox.clear_widgets()
        with connect() as c: rows=c.execute('SELECT id,content FROM notes WHERE username=? ORDER BY id DESC',(self.app.username,)).fetchall()
        for r in rows:
            card=Card(orientation='vertical',size_hint_y=None,height=dp(105)); card.add_widget(label(r['content'],14,DARK,height=50)); card.add_widget(btn('حذف',lambda nid=r['id']:self.delete(nid))); self.listbox.add_widget(card)
    def delete(self,nid):
        with connect() as c:c.execute('DELETE FROM notes WHERE id=? AND username=?',(nid,self.app.username))
        self.render()

class Settings(Base):
    def on_pre_enter(self):
        self.shell('تنظیمات حساب'); self.body.add_widget(label('نام کاربری: '+self.app.username,16,TEAL,True)); self.old=field('رمز فعلی',True); self.new=field('رمز جدید (حداقل ۸ نویسه)',True); self.confirm=field('تکرار رمز جدید',True)
        for w in (self.old,self.new,self.confirm):self.body.add_widget(w)
        self.body.add_widget(btn('تغییر رمز عبور',self.update,True)); self.body.add_widget(label('IRANIAN MIGHT • Android Edition',12,MUTED))
    def update(self):
        if self.new.text!=self.confirm.text:self.msg('خطا','تکرار رمز جدید یکسان نیست.'); return
        ok,m=change_pw(self.app.username,self.old.text,self.new.text); self.msg('تنظیمات',m)
        if ok:self.old.text=self.new.text=self.confirm.text=''

class IranianMightApp(App):
    username=''
    def build(self):
        self.title='IRANIAN MIGHT'; Window.clearcolor=BG; init_db(); sm=ScreenManager(transition=SlideTransition(duration=.16))
        for name,cls in [('login',LoginScreen),('dashboard',Dashboard),('bios',Bios),('notes',Notes),('settings',Settings)]:sm.add_widget(cls(name=name))
        sm.current='login'; self.sm=sm; return sm
    def go(self,name): self.sm.current=name

if __name__=='__main__': IranianMightApp().run()
