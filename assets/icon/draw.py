"""Рисует иконки VPN-TLS (PNG). Запуск: python3 draw.py  (нужен Pillow).

app-<size>.png   — иконка приложения: синий градиент, белый щит с замочной скважиной
tray-on/off/wait-<size>.png — иконки в трее: подключено / отключено / подключение
"""
from PIL import Image, ImageDraw

S = 1024  # рисуем крупно, потом уменьшаем — так края гладкие


def shield(d, cx, cy, w, h, fill):
    # щит: верх с плечами, бока сходятся к острию снизу
    top = cy - h * 0.5
    pts = []
    import math
    # верхняя кромка с лёгким прогибом вниз к центру
    for i in range(0, 41):
        t = i / 40
        x = cx - w / 2 + w * t
        y = top + h * 0.035 * math.sin(math.pi * t)
        pts.append((x, y))
    # правый бок → остриё → левый бок (кривые Безье упрощённо)
    def bez(p0, p1, p2, n=40):
        out = []
        for i in range(1, n + 1):
            t = i / n
            out.append(((1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t * t * p2[0],
                        (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t * t * p2[1]))
        return out
    pts += bez((cx + w / 2, top), (cx + w / 2, cy + h * 0.25), (cx, cy + h * 0.5))
    pts += bez((cx, cy + h * 0.5), (cx - w / 2, cy + h * 0.25), (cx - w / 2, top))
    d.polygon(pts, fill=fill)


def keyhole(d, cx, cy, r, fill):
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fill)
    d.polygon([(cx - r * 0.45, cy + r * 0.3), (cx + r * 0.45, cy + r * 0.3),
               (cx + r * 0.7, cy + r * 2.3), (cx - r * 0.7, cy + r * 2.3)], fill=fill)


def gradient(c1, c2):
    g = Image.new("RGBA", (S, S))
    gd = ImageDraw.Draw(g)
    for y in range(S):
        t = y / (S - 1)
        gd.line([(0, y), (S, y)], fill=tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3)) + (255,))
    return g


def rounded_mask(radius):
    m = Image.new("L", (S, S), 0)
    ImageDraw.Draw(m).rounded_rectangle([0, 0, S - 1, S - 1], radius=radius, fill=255)
    return m


def app_icon():
    bg = gradient((37, 99, 235), (14, 165, 233))
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    img.paste(bg, (0, 0), rounded_mask(int(S * 0.22)))
    d = ImageDraw.Draw(img)
    shield(d, S / 2, S * 0.52, S * 0.56, S * 0.66, (255, 255, 255, 255))
    keyhole(d, S / 2, S * 0.44, S * 0.075, (30, 110, 235, 255))
    return img


def tray_icon(color):
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    img.paste(Image.new("RGBA", (S, S), color + (255,)), (0, 0), rounded_mask(int(S * 0.24)))
    d = ImageDraw.Draw(img)
    shield(d, S / 2, S * 0.53, S * 0.62, S * 0.74, (255, 255, 255, 255))
    keyhole(d, S / 2, S * 0.45, S * 0.085, color + (255,))
    return img


def save(img, name, sizes):
    for s in sizes:
        img.resize((s, s), Image.LANCZOS).save(f"{name}-{s}.png")


save(app_icon(), "app", [16, 20, 24, 32, 40, 48, 64, 96, 128, 256])
tray = [16, 20, 24, 32, 40, 48, 64]
save(tray_icon((22, 163, 74)), "tray-on", tray)
save(tray_icon((107, 114, 128)), "tray-off", tray)
save(tray_icon((217, 119, 6)), "tray-wait", tray)
