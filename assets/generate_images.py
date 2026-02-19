#!/usr/bin/env python3
"""Generate MCP logo images in PNG, GIF, and JPEG formats."""

from PIL import Image, ImageDraw, ImageFont
import os

# Image dimensions
WIDTH = 300
HEIGHT = 100

# Colors - purple gradient approximation
TEXT_COLOR = (0, 51, 153)  # Dark blue color


def create_mcp_image():
    """Create an image with 'MCP' text on transparent background."""
    # Create RGBA image with transparent background
    img = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Try to load a bold font
    font_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
    ]

    font = None
    font_size = 72

    for font_path in font_paths:
        if os.path.exists(font_path):
            try:
                font = ImageFont.truetype(font_path, font_size)
                break
            except Exception:
                continue

    if font is None:
        # Fallback to default font
        font = ImageFont.load_default()

    # Draw the text centered
    text = "MCP"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]

    x = (WIDTH - text_width) // 2
    y = (HEIGHT - text_height) // 2 - bbox[1]  # Adjust for font baseline

    draw.text((x, y), text, font=font, fill=TEXT_COLOR)

    return img


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Generate the base image
    img = create_mcp_image()

    # Save as PNG (supports transparency)
    png_path = os.path.join(script_dir, "mcp.png")
    img.save(png_path, "PNG")
    print(f"Created: {png_path}")

    # Save as GIF (supports transparency)
    gif_path = os.path.join(script_dir, "mcp.gif")
    # Convert to palette mode for GIF, preserving transparency
    gif_img = img.convert("P", palette=Image.ADAPTIVE, colors=255)
    # Set transparency
    mask = img.split()[3]  # Get alpha channel
    gif_img.info["transparency"] = 0
    gif_img.save(gif_path, "GIF", transparency=0)
    print(f"Created: {gif_path}")

    # Save as JPEG (no transparency - use white background)
    jpeg_path = os.path.join(script_dir, "mcp.jpeg")
    # Create white background and composite
    jpeg_img = Image.new("RGB", (WIDTH, HEIGHT), (255, 255, 255))
    jpeg_img.paste(img, mask=img.split()[3])  # Use alpha as mask
    jpeg_img.save(jpeg_path, "JPEG", quality=95)
    print(f"Created: {jpeg_path}")

    # Save as WebP (supports transparency)
    webp_path = os.path.join(script_dir, "mcp.webp")
    img.save(webp_path, "WEBP", quality=95, lossless=True)
    print(f"Created: {webp_path}")

    # Save as AVIF (supports transparency)
    avif_path = os.path.join(script_dir, "mcp.avif")
    img.save(avif_path, "AVIF", quality=95)
    print(f"Created: {avif_path}")


if __name__ == "__main__":
    main()