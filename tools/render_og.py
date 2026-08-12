from PIL import Image, ImageDraw, ImageFont

W, H = 1200, 630

bg = (20, 18, 15)       # #14120F
seal_color = (242, 237, 229)  # #F2EDE5
muted = (154, 143, 131)       # #9A8F83
rule = (46, 42, 37)           # #2E2A25
dim = (107, 98, 90)           # #6B625A

img = Image.new("RGB", (W, H), bg)
draw = ImageDraw.Draw(img)

# Border
draw.rounded_rectangle([40, 40, 1160, 590], radius=24, outline=rule, width=1)

# Seal mark
cx, cy, r = 180, 315, 140
# Fill circle with seal color first
draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=seal_color)
# Right half: draw bg-colored rectangle over right side
draw.rectangle([cx, cy - r, cx + r + 2, cy + r + 2], fill=bg)
# Left half lines: draw bg-colored strips
for y_offset in [-75, -35, 5, 45]:
    y = cy + y_offset
    draw.rectangle([cx - r, y - 6, cx + 2, y + 6], fill=bg)
# Outer ring
draw.ellipse([cx - r - 8, cy - r - 8, cx + r + 8, cy + r + 8],
             outline=seal_color, width=8)

# Fonts
try:
    title_font = ImageFont.truetype("C:\\Windows\\Fonts\\segoeuib.ttf", 72)
    mono20 = ImageFont.truetype("C:\\Windows\\Fonts\\consola.ttf", 20)
    body_font = ImageFont.truetype("C:\\Windows\\Fonts\\segoeuil.ttf", 32)
    mono14 = ImageFont.truetype("C:\\Windows\\Fonts\\consola.ttf", 14)
except Exception:
    title_font = body_font = mono20 = mono14 = ImageFont.load_default()

draw.text((360, 250), "SELO", fill=seal_color, font=title_font)
draw.text((360, 330), "CRYPTOGRAPHIC ACCOUNTING & ZK AUDIT ENGINE",
          fill=muted, font=mono20)
draw.line([(360, 360), (830, 360)], fill=rule, width=1)
draw.text((360, 390), "Agent-kept books for stablecoin payments.",
          fill=dim, font=body_font)
draw.text((360, 440), "Poseidon BN254 commitments via human T1 signatures.",
          fill=dim, font=body_font)

# Tags
tag_y = 480
labels = ["Tier 1 Solution", "Poseidon BN254", "287 Core Tests"]
for i, label in enumerate(labels):
    x = 360 + i * 155
    tw = len(label) * 11
    draw.rounded_rectangle([x, tag_y, x + tw, tag_y + 28], radius=14, fill=rule)
    draw.text((x + 20, tag_y + 6), label, fill=muted, font=mono14)

img.save(r"C:\Users\user\Desktop\selo-one-pager\public\selo-og.png")
print("PNG created: {}x{}".format(*img.size))
