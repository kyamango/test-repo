import os
import sys
import random
from PIL import Image, ImageDraw, ImageFont, ImageColor, ImageEnhance
import re
from pathlib import Path
import glob
import numpy as np
from collections import defaultdict
import hashlib
import json
from datetime import datetime, timezone
import base64
import uuid
import platform
import argparse
import requests
from cryptography.fernet import Fernet
import socket
import math
from PIL import ImageFilter
from core.lib.github_validator import GitHubLicenseValidator

def get_base_dir():
    """Get base directory (parent of core folder)"""
    current_dir = os.path.dirname(os.path.abspath(__file__))  # Get tools dir
    core_dir = os.path.dirname(current_dir)  # Get core dir
    return os.path.dirname(core_dir)  # Get project root dir

def get_character_dir(category=None):
    """Get character images directory path"""
    base_dir = get_image_gen_dir()
    
    # Handle special categories or use niche name
    if category in ["profile", "page"]:
        # For special categories, use their specific folders
        char_dir = os.path.join(base_dir, "character", category)
    else:
        # For other categories, use the category name directly
        char_dir = os.path.join(base_dir, "character", category) if category else os.path.join(base_dir, "character", get_niche_name())
    
    # Ensure directory exists
    os.makedirs(char_dir, exist_ok=True)
    print(f"Using character directory: {char_dir}")
    
    return char_dir

def get_active_language():
    """Get active language from config/language.txt"""
    config_file = os.path.join(get_base_dir(), "config", "language.txt")
    try:
        if os.path.exists(config_file):
            with open(config_file, "r", encoding="utf-8") as f:
                return f.read().strip()
    except Exception as e:
        print(f"Error reading language config: {e}")
    return "default"

def get_niche_name():
    """Get niche name from active language's kw/niche.txt"""
    lang_path = os.path.join(get_base_dir(), "languages", get_active_language())
    niche_file = os.path.join(lang_path, "kw", "niche.txt")
    try:
        if os.path.exists(niche_file):
            with open(niche_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return content.split('\n')[0].strip()
    except Exception as e:
        print(f"Error reading niche file: {e}")
    return "blog"  # Default fallback

# Check GitHub license
def check_license():
    """Check license before running in GitHub Actions"""
    if os.getenv("GITHUB_ACTIONS"):
        validator = GitHubLicenseValidator()
        if not validator.verify_license():
            print("❌ GitHub license validation failed")
            sys.exit(1)
        return True
    return True

# Run license check at start
if not check_license():
    sys.exit(1)

def get_repo_path():
    """Get repository root path"""
    return get_base_dir()

def get_project_path(project_name=None):
    """Get project path"""
    if project_name:
        # If project name provided, it's under Hugo projects folder
        return os.path.join("C:", "Hugo", "projects", project_name)
    else:
        # If no project name, use current repo path
        return get_base_dir()

def get_content_dir():
    """Get content directory path"""
    return os.path.join(get_base_dir(), "content")

def get_content_category_path(category=None):
    """Get content directory path for category"""
    content_dir = get_content_dir()
    if category in ["profile", "page"]:
        return os.path.join(content_dir, category)
    else:
        niche_name = get_niche_name()
        return os.path.join(content_dir, niche_name)

def get_static_category_path(category=None):
    """Get static images directory path for category"""
    base_dir = get_base_dir()
    
    # Handle special categories first
    if category in ["profile", "page"]:
        return os.path.join(base_dir, "static", "images", category)
    
    # Get niche name for dynamic categories
    niche_name = get_niche_name()
    
    # Map content structure to static/images structure
    if category:
        return os.path.join(base_dir, "static", "images", category)
    else:
        return os.path.join(base_dir, "static", "images", niche_name)

def get_static_dir():
    """Get static directory path"""
    return os.path.join(get_base_dir(), "static")

def get_image_gen_dir():
    """Get image-generator directory path"""
    return os.path.join(get_base_dir(), "image-generator")

def scan_for_new_articles():
    """Scan for new articles without images in all categories"""
    content_path = os.path.join(get_repo_path(), "content")
    
    # Check if the content directory exists
    if not os.path.exists(content_path):
        print(f"Content directory not found: {content_path}")
        return []
    
    # Scan all categories
    articles_to_process = []
    
    try:
        categories = [d for d in os.listdir(content_path) 
                     if os.path.isdir(os.path.join(content_path, d))]
        
        for category in categories:
            # Get articles without images
            articles_without_images = get_articles_without_images("", category)
            
            if articles_without_images:
                print(f"Found {len(articles_without_images)} articles without images in '{category}'")
                for article in articles_without_images:
                    articles_to_process.append((article, category))
    
    except Exception as e:
        print(f"Error saat scanning artikel: {e}")
        
    return articles_to_process

def extract_title_from_md(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            
            # Try to find title in frontmatter
            title_match = re.search(r'title:\s*["\']?(.*?)["\']?\s*$', content, re.MULTILINE)
            
            if title_match:
                return title_match.group(1).strip()
            else:
                # If no title in frontmatter, use filename
                return os.path.splitext(os.path.basename(file_path))[0]
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return os.path.splitext(os.path.basename(file_path))[0]

def sanitize_filename(title):
    # Convert to lowercase
    valid_filename = title.lower()
    
    # Remove invalid filename characters
    valid_filename = re.sub(r'[\\/*?:"<>|]', "", valid_filename)
    
    # Replace spaces and other separators with single hyphen
    valid_filename = re.sub(r'[\s\-–—]+', "-", valid_filename)
    
    # Remove apostrophes and quotes
    valid_filename = valid_filename.replace("'", "").replace('"', "")
    
    # Replace multiple hyphens with single hyphen
    valid_filename = re.sub(r'-+', "-", valid_filename)
    
    # Remove leading and trailing hyphens
    valid_filename = valid_filename.strip("-")
    
    return valid_filename

def get_articles_without_images(project_name, category):
    """Find articles that don't have images or image links"""
    articles_dir = Path(os.path.join(get_project_path(project_name), "content", category))
    output_dir = Path(os.path.join(get_project_path(project_name), "static", "images", category))
    
    md_files = list(articles_dir.glob("*.md"))
    articles_without_images = []
    
    for md_file in md_files:
        with open(md_file, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Check if the article already has a featuredImage with actual value
        has_featured_image = bool(re.search(r'featuredImage:\s*["\']([^"\'\s]+)["\']', content))
        
        # Check if article has image link in content
        has_image_link = bool(re.search(r'!\[.*?\]\(/images/' + re.escape(category) + r'/.*?\)', content))
        
        # Add to list if no featured image AND no image link
        if not has_featured_image and not has_image_link:
            articles_without_images.append(md_file)
    
    return articles_without_images

def is_duplicate_image(image_path, output_dir):
    """Check if image is a duplicate by comparing with existing images"""
    if not os.path.exists(image_path):
        return False
    
    # Get file name without extension
    base_name = os.path.splitext(os.path.basename(image_path))[0]
    
    # First check if a file with the same name already exists in the directory
    existing_files = list(output_dir.glob(f"{base_name}.*"))
    if existing_files and os.path.exists(existing_files[0]):
        # Only consider it a duplicate if it has the same filename
        print(f"A file with the same name already exists: {os.path.basename(existing_files[0])}")
        return True
    
    # If we're worried about visual duplicates regardless of filename,
    # we can do a basic image hash comparison, but make it less strict
    try:
        new_image = Image.open(image_path)
        # Convert to small grayscale image for basic comparison
        new_image = new_image.resize((8, 8), Image.Resampling.LANCZOS).convert('L')
        new_image_data = list(new_image.getdata())
        
        # Check each existing image - but skip if same basename to avoid self-comparison
        for existing_file in output_dir.glob("*.png"):
            existing_basename = os.path.splitext(os.path.basename(existing_file))[0]
            if existing_basename == base_name:
                continue
                
            try:
                existing_image = Image.open(existing_file)
                existing_image = existing_image.resize((8, 8), Image.Resampling.LANCZOS).convert('L')
                existing_data = list(existing_image.getdata())
                
                # Calculate basic difference
                diff = sum(abs(a - b) for a, b in zip(new_image_data, existing_data))
                avg_diff = diff / (8 * 8)
                
                # If images are very similar (low average difference)
                if avg_diff < 10:  # Threshold value - higher means less strict
                    print(f"Very similar images were detected with: {os.path.basename(existing_file)}")
                    return True
            except Exception as e:
                print(f"Error comparing with existing image: {e}")
                continue
    except Exception as e:
        print(f"Error opening new image for comparison: {e}")
    
    return False

def get_default_config_values():
    """Return default configuration values for all settings in one central place"""
    return {
        "gradient_colors": [
            ("#FF5733", "#581845"),
            ("#00A8CC", "#FFD700"),
            ("#7B68EE", "#FF1493"),
            ("#32CD32", "#FF8C00"),
            ("#4169E1", "#FF4500"),
            ("#9400D3", "#FF6347"),
            ("#1E90FF", "#FF69B4"),
            ("#2E8B57", "#FFD700")
        ],
        "font_size": 38,  # Default font size
        "font_sizes": {
            "small": 28,
            "medium": 38,
            "large": 48
        },
        "character_style": "center-normal",
        "character_styles": [
            # Original styles
            "left-normal", "right-normal", "center-normal", 
            "left-square", "left-circle", "left-rounded",
            "right-square", "right-circle", "right-rounded",
            "center-square", "center-circle", "center-rounded",
            # Border variants
            "left-normal-border", "right-normal-border", "center-normal-border",
            "left-square-border", "left-circle-border", "left-rounded-border",
            "right-square-border", "right-circle-border", "right-rounded-border", 
            "center-square-border", "center-circle-border", "center-rounded-border",
            # Shadow variants
            "left-normal-shadow", "right-normal-shadow", "center-normal-shadow",
            "left-square-shadow", "left-circle-shadow", "left-rounded-shadow",
            "right-square-shadow", "right-circle-shadow", "right-rounded-shadow",
            "center-square-shadow", "center-circle-shadow", "center-rounded-shadow",
            # Blur variants
            "left-normal-blur", "right-normal-blur", "center-normal-blur",
            "left-square-blur", "left-circle-blur", "left-rounded-blur", 
            "right-square-blur", "right-circle-blur", "right-rounded-blur",
            "center-square-blur", "center-circle-blur", "center-rounded-blur",
            # Combined effect variants
            "left-normal-combo", "right-normal-combo", "center-normal-combo",
            "left-square-combo", "left-circle-combo", "left-rounded-combo",
            "right-square-combo", "right-circle-combo", "right-rounded-combo",
            "center-square-combo", "center-circle-combo", "center-rounded-combo",
            # New half-image styles with vertical blur border
            "left-half", "right-half",
            # New diagonal styles with diagonal blur border
            "left-diagonal", "right-diagonal", 
            # New curved styles with curved blur border
            "left-curve", "right-curve"
        ],
        "text_style": "center-normal",
        "text_styles": {
            "positions": {
                "left": (30, "center"),
                "right": (-30, "center"),
                "center": ("center", "center"),
                "top": ("center", 30),
                "bottom": ("center", -30),
                "top-left": (30, 30),
                "top-right": (-30, 30),
                "bottom-left": (30, -30),
                "bottom-right": (-30, -30),
            },
            "fonts": {
                "normal": "",
                "italic": "_italic",
                "oblique": "_oblique", 
                "bold": "_bold",
                "bold-italic": "_bold_italic",
                "bold-oblique": "_bold_oblique"
            },
            "valid_styles": [
                "left-normal", "left-italic", "left-oblique",
                "left-bold", "left-bold-italic", "left-bold-oblique",
                "right-normal", "right-italic", "right-oblique",
                "right-bold", "right-bold-italic", "right-bold-oblique",
                "center-normal", "center-italic", "center-oblique",
                "center-bold", "center-bold-italic", "center-bold-oblique",
                "top-left-normal", "top-left-italic", "top-left-oblique",
                "top-left-bold", "top-left-bold-italic", "top-left-bold-oblique",
                "top-right-normal", "top-right-italic", "top-right-oblique",
                "top-right-bold", "top-right-bold-italic", "top-right-bold-oblique",
                "bottom-left-normal", "bottom-left-italic", "bottom-left-oblique",
                "bottom-left-bold", "bottom-left-bold-italic", "bottom-left-bold-oblique",
                "bottom-right-normal", "bottom-right-italic", "bottom-right-oblique",
                "bottom-right-bold", "bottom-right-bold-italic", "bottom-right-bold-oblique"
            ]
        }
    }

def ensure_directory_structure():
    """Ensure all required directories exist"""
    base_dir = get_base_dir()
    niche_name = get_niche_name()
    lang_path = os.path.join(base_dir, "languages", get_active_language())
    
    # List of required directories
    dirs = [
        # Content directories
        os.path.join(base_dir, "content", "profile"),
        os.path.join(base_dir, "content", "page"),
        os.path.join(base_dir, "content", niche_name),
        
        # Static image directories 
        os.path.join(base_dir, "static", "images", "profile"),
        os.path.join(base_dir, "static", "images", "page"),
        os.path.join(base_dir, "static", "images", niche_name),
        
        # Image generator directories
        os.path.join(base_dir, "image-generator", "watermark"),
        os.path.join(base_dir, "image-generator", "vector"),
        os.path.join(base_dir, "image-generator", "fonts"),
        os.path.join(base_dir, "image-generator", "colors"),
        os.path.join(base_dir, "image-generator", "character", "profile"),
        os.path.join(base_dir, "image-generator", "character", "page"),
        os.path.join(base_dir, "image-generator", "character", niche_name)
    ]
    
    for directory in dirs:
        os.makedirs(directory, exist_ok=True)

def ensure_default_config():
    """Ensure all default configuration files exist"""
    config_files = {
        os.path.join(get_image_gen_dir(), "colors", "gradient.default.txt"): ("gradient_colors", True),
        os.path.join(get_image_gen_dir(), "colors", "gradient.txt"): ("gradient_colors", True),
        os.path.join(get_image_gen_dir(), "character", "character_style.default.txt"): ("character_style", False),
        os.path.join(get_image_gen_dir(), "character", "character_style.txt"): ("character_style", False),
        os.path.join(get_image_gen_dir(), "fonts", "text_style.default.txt"): ("text_style", False),
        os.path.join(get_image_gen_dir(), "fonts", "text_style.txt"): ("text_style", False),
        os.path.join(get_image_gen_dir(), "fonts", "font_size.txt"): ("font_size", False),
    }
    
    default_values = get_default_config_values()
    
    for file_path, (config_key, is_list) in config_files.items():
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # Skip if file already exists
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                continue
                
            print(f"Creating config file: {file_path}")
            
            # Write content based on whether it's a list or single value
            with open(file_path, 'w', encoding='utf-8') as file:
                if is_list:
                    # For list values like gradient colors
                    for start_color, end_color in default_values[config_key]:
                        file.write(f"{start_color}, {end_color}\n")
                else:
                    # For single values like text style
                    file.write(default_values[config_key])
            
            print(f"Created config file: {file_path}")
        except Exception as e:
            print(f"Error creating config file {file_path}: {e}")
            import traceback
            traceback.print_exc()
    
    print("Default configuration files check completed")

def get_font_size_from_file():
    """Read font size preference from file"""
    size_file = os.path.join(get_image_gen_dir(), "fonts", "font_size.txt")
    default_values = get_default_config_values()
    default_size = default_values["font_size"]
    
    try:
        if not os.path.exists(size_file):
            # Create default font size file
            os.makedirs(os.path.dirname(size_file), exist_ok=True)
            with open(size_file, 'w', encoding='utf-8') as f:
                f.write(str(default_size))
            return default_size
            
        with open(size_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            
            # Check numeric size
            if content.isdigit():
                size = int(content)
                if 10 <= size <= 100:
                    return size
                else:
                    print(f"Font size must be between 10-100, got: {size}")
                    return default_size
            
            # Check preset sizes
            elif content.lower() in default_values["font_sizes"]:
                return default_values["font_sizes"][content.lower()]
            
            print(f"Invalid font size format: {content}, using default: {default_size}")
            return default_size
            
    except Exception as e:
        print(f"Error reading font size: {e}")
        return default_size

def create_blur_mask(size, blur_type, position, blur_intensity=5):
    """Create blur mask for different character styles"""
    width, height = size
    mask = Image.new('L', size, 0)
    draw = ImageDraw.Draw(mask)
    
    if blur_type == "vertical":
        # Vertical blur border - for half style
        if position == "left":
            # Character on the left, blur border on the right
            # Character area: 60% from the left (480px of 800px)
            char_area_width = int(width * 0.6)
            draw.rectangle((0, 0, char_area_width, height), fill=255)
            
            # Create gradient blur effect on the right border
            for i in range(blur_intensity * 2):
                alpha = int(255 * (1 - i / (blur_intensity * 2)))
                x = char_area_width + i
                if x < width:
                    for y in range(height):
                        current_pixel = mask.getpixel((min(x, width-1), y))
                        if current_pixel == 0:
                            draw.point((x, y), fill=alpha)
        else:  # right
            # Character on the right, blur border on the left
            # Character area: 60% from the right (480px of 800px)
            char_area_width = int(width * 0.6)
            char_start_x = width - char_area_width
            draw.rectangle((char_start_x, 0, width, height), fill=255)
            
            # Create gradient blur effect on the left border
            for i in range(blur_intensity * 2):
                alpha = int(255 * (1 - i / (blur_intensity * 2)))
                x = char_start_x - i - 1
                if x >= 0:
                    for y in range(height):
                        current_pixel = mask.getpixel((max(x, 0), y))
                        if current_pixel == 0:
                            draw.point((x, y), fill=alpha)
    
    elif blur_type == "diagonal":
        # Diagonal blur border - for diagonal style
        if position == "left":
            # Character area: diagonal from top-left to bottom with max width 60%
            top_width = int(width * 0.1)  # Start from 10% width
            max_width = int(width * 0.6)  # Maximum 60% width
            
            for y in range(height):
                # Calculate width at this y position
                progress = y / height
                current_width = int(top_width + (max_width - top_width) * progress)
                
                # Fill main area
                if current_width > 0:
                    draw.line([(0, y), (current_width, y)], fill=255)
                
                # Add blur effect at diagonal edge
                for i in range(blur_intensity):
                    alpha = int(255 * (1 - i / blur_intensity))
                    blur_x = current_width + i
                    if blur_x < width:
                        draw.point((blur_x, y), fill=alpha)
        else:  # right
            # Character area: diagonal from top-right to bottom with max width 60%
            top_width = int(width * 0.1)  # Start from 10% width
            max_width = int(width * 0.6)  # Maximum 60% width
            
            for y in range(height):
                # Calculate width at this y position
                progress = y / height
                current_width = int(top_width + (max_width - top_width) * progress)
                start_x = width - current_width
                
                # Fill main area
                if current_width > 0 and start_x >= 0:
                    draw.line([(start_x, y), (width, y)], fill=255)
                
                # Add blur effect at diagonal edge
                for i in range(blur_intensity):
                    alpha = int(255 * (1 - i / blur_intensity))
                    blur_x = start_x - i - 1
                    if blur_x >= 0:
                        draw.point((blur_x, y), fill=alpha)
    
    elif blur_type == "curve":
        # Curved blur border - for curve style
        center_x = width // 2
        max_char_width = int(width * 0.6)  # Maximum 60% width for character
        curve_amplitude = width // 6  # Curve amplitude
        
        for y in range(height):
            # Create sine wave for curve effect
            wave_offset = int(curve_amplitude * math.sin(2 * math.pi * y / height))
            
            if position == "left":
                # Left curve: character on the left with curved border
                # Base width is 60% of total, then adjusted with wave
                base_width = max_char_width
                curve_x = min(base_width + wave_offset, width - 1)
                curve_x = max(curve_x, 0)
                
                # Fill character area
                if curve_x > 0:
                    draw.line([(0, y), (curve_x, y)], fill=255)
                
                # Add blur transition
                for i in range(blur_intensity):
                    alpha = int(255 * (1 - i / blur_intensity))
                    blur_x = curve_x + i + 1
                    if blur_x < width:
                        draw.point((blur_x, y), fill=alpha)
                        
            else:  # right
                # Right curve: character on the right with curved border
                base_width = max_char_width
                curve_x = max(width - base_width - wave_offset, 0)
                curve_x = min(curve_x, width - 1)
                
                # Fill character area
                if curve_x < width:
                    draw.line([(curve_x, y), (width, y)], fill=255)
                
                # Add blur transition
                for i in range(blur_intensity):
                    alpha = int(255 * (1 - i / blur_intensity))
                    blur_x = curve_x - i - 1
                    if blur_x >= 0:
                        draw.point((blur_x, y), fill=alpha)
    
    return mask

def apply_enhanced_effects(char_img, effect_type, shape="normal"):
    """Apply enhanced visual effects to character image"""
    try:
        original_size = char_img.size
        
        if effect_type == "border":
            return apply_border_effect(char_img, shape)
        elif effect_type == "shadow":
            return apply_shadow_effect(char_img, shape)  
        elif effect_type == "blur":
            return apply_blur_effect(char_img, shape)
        elif effect_type == "combo":
            return apply_combo_effect(char_img, shape)
        else:
            return char_img
            
    except Exception as e:
        print(f"Error applying enhanced effects: {e}")
        return char_img

def apply_border_effect(char_img, shape="normal"):
    """Apply thin and smooth border effect to character image"""
    try:
        # Make border thinner - reduce from 1/20 to 1/40 of image size
        border_width = max(2, min(char_img.size) // 40)  # Thinner border
        
        # Expand canvas for border
        new_width = char_img.width + border_width * 2
        new_height = char_img.height + border_width * 2
        
        # Create new canvas with transparent background
        bordered_img = Image.new('RGBA', (new_width, new_height), (0, 0, 0, 0))
        
        # Create border mask
        border_mask = Image.new('L', (new_width, new_height), 0)
        border_draw = ImageDraw.Draw(border_mask)
        
        # Create main content mask
        content_mask = Image.new('L', char_img.size, 0)
        content_draw = ImageDraw.Draw(content_mask)
        
        if shape == "normal":
            # Keep original shape, add subtle border
            if char_img.mode == 'RGBA':
                alpha = char_img.split()[-1]
                # Create smoother border effect
                from PIL import ImageFilter
                expanded_alpha = alpha.resize((new_width, new_height), Image.Resampling.LANCZOS)
                border_alpha = expanded_alpha.filter(ImageFilter.GaussianBlur(border_width/2))
                bordered_img.putalpha(border_alpha)
                
                # Use semi-transparent white for border
                border_color = (255, 255, 255, 120)  # Reduced opacity for softer look
                border_layer = Image.new('RGBA', (new_width, new_height), border_color)
                bordered_img = Image.alpha_composite(border_layer, bordered_img)
        
        elif shape == "square":
            # Thin square border
            border_draw.rectangle((0, 0, new_width, new_height), fill=255)
            content_draw.rectangle((0, 0, char_img.width, char_img.height), fill=255)
            
        elif shape == "circle":
            # Thin circular border
            border_draw.ellipse((0, 0, new_width, new_height), fill=255)
            content_draw.ellipse((0, 0, char_img.width, char_img.height), fill=255)
            
        elif shape == "rounded":
            # Thin rounded rectangle border
            border_radius = min(new_width, new_height) // 12  # Smaller radius for thinner look
            content_radius = min(char_img.width, char_img.height) // 12
            border_draw.rounded_rectangle((0, 0, new_width, new_height), radius=border_radius, fill=255)
            content_draw.rounded_rectangle((0, 0, char_img.width, char_img.height), radius=content_radius, fill=255)
        
        if shape != "normal":
            # Apply semi-transparent white border
            border_color = Image.new('RGBA', (new_width, new_height), (255, 255, 255, 120))
            border_color.putalpha(border_mask)
            bordered_img = Image.alpha_composite(bordered_img, border_color)
            
            # Apply character image with mask
            char_img.putalpha(content_mask)
        
        # Paste character image in center
        paste_x = border_width
        paste_y = border_width
        
        # Add slight blur to border edges for smoothness
        if shape != "normal":
            bordered_img = bordered_img.filter(ImageFilter.GaussianBlur(0.5))
        
        # Paste character with original alpha
        if char_img.mode == 'RGBA':
            bordered_img.paste(char_img, (paste_x, paste_y), char_img)
        else:
            bordered_img.paste(char_img, (paste_x, paste_y))
        
        return bordered_img
        
    except Exception as e:
        print(f"Error in apply_border_effect: {e}")
        return char_img

def apply_shadow_effect(char_img, shape="normal"):
    """Apply shadow effect to character image"""
    try:
        # Shadow parameters
        shadow_offset_x = max(3, char_img.width // 40)
        shadow_offset_y = max(3, char_img.height // 40)
        shadow_blur_radius = max(2, min(char_img.size) // 30)
        
        # Expand canvas for shadow
        padding = shadow_blur_radius * 2 + max(shadow_offset_x, shadow_offset_y)
        new_width = char_img.width + padding * 2
        new_height = char_img.height + padding * 2
        
        # Create shadow canvas
        shadow_img = Image.new('RGBA', (new_width, new_height), (0, 0, 0, 0))
        
        # Create shadow mask
        shadow_mask = Image.new('L', char_img.size, 0)
        shadow_draw = ImageDraw.Draw(shadow_mask)
        
        if shape == "normal":
            # Use original alpha channel for shadow shape
            if char_img.mode == 'RGBA':
                shadow_mask = char_img.split()[-1]
        elif shape == "square":
            shadow_draw.rectangle((0, 0, char_img.width, char_img.height), fill=255)
        elif shape == "circle":
            shadow_draw.ellipse((0, 0, char_img.width, char_img.height), fill=255)
        elif shape == "rounded":
            radius = min(char_img.width, char_img.height) // 8
            shadow_draw.rounded_rectangle((0, 0, char_img.width, char_img.height), radius=radius, fill=255)
        
        # Create shadow
        shadow_color = Image.new('RGBA', char_img.size, (0, 0, 0, 120))  # Semi-transparent black
        shadow_color.putalpha(shadow_mask)
        
        # Apply blur to shadow
        from PIL import ImageFilter
        shadow_color = shadow_color.filter(ImageFilter.GaussianBlur(shadow_blur_radius))
        
        # Position shadow with offset
        shadow_x = padding + shadow_offset_x
        shadow_y = padding + shadow_offset_y
        shadow_img.paste(shadow_color, (shadow_x, shadow_y), shadow_color)
        
        # Position main character image
        char_x = padding
        char_y = padding
        
        # Apply shape mask to character if needed
        if shape != "normal":
            char_mask = Image.new('L', char_img.size, 0)
            char_draw = ImageDraw.Draw(char_mask)
            
            if shape == "square":
                char_draw.rectangle((0, 0, char_img.width, char_img.height), fill=255)
            elif shape == "circle":
                char_draw.ellipse((0, 0, char_img.width, char_img.height), fill=255)
            elif shape == "rounded":
                radius = min(char_img.width, char_img.height) // 8
                char_draw.rounded_rectangle((0, 0, char_img.width, char_img.height), radius=radius, fill=255)
            
            char_img.putalpha(char_mask)
        
        # Composite character over shadow
        if char_img.mode == 'RGBA':
            shadow_img.paste(char_img, (char_x, char_y), char_img)
        else:
            shadow_img.paste(char_img, (char_x, char_y))
        
        return shadow_img
        
    except Exception as e:
        print(f"Error in apply_shadow_effect: {e}")
        return char_img

def apply_blur_effect(char_img, shape="normal"):
    """Apply subtle blur effect to character image edges"""
    try:
        from PIL import ImageFilter
        
        # Create mask for shape
        if shape != "normal":
            mask = Image.new('L', char_img.size, 0)
            draw = ImageDraw.Draw(mask)
            
            if shape == "square":
                draw.rectangle((0, 0, char_img.width, char_img.height), fill=255)
            elif shape == "circle":
                draw.ellipse((0, 0, char_img.width, char_img.height), fill=255)
            elif shape == "rounded":
                radius = min(char_img.width, char_img.height) // 8
                draw.rounded_rectangle((0, 0, char_img.width, char_img.height), radius=radius, fill=255)
            
            # Apply shape mask
            char_img.putalpha(mask)
        
        # Create soft edge blur effect
        blur_radius = max(1, min(char_img.size) // 50)  # Subtle blur
        
        # Create a slightly blurred version
        blurred = char_img.filter(ImageFilter.GaussianBlur(blur_radius))
        
        # Create edge mask for blending
        if char_img.mode == 'RGBA':
            alpha = char_img.split()[-1]
            # Create inner and outer masks
            inner_mask = alpha.filter(ImageFilter.MinFilter(3))  # Shrink slightly
            
            # Blend original with blurred using edge detection
            result = Image.composite(char_img, blurred, inner_mask)
            return result
        else:
            # For non-RGBA images, apply subtle blur to entire image
            return char_img.filter(ImageFilter.GaussianBlur(blur_radius * 0.5))
        
    except Exception as e:
        print(f"Error in apply_blur_effect: {e}")
        return char_img

def apply_combo_effect(char_img, shape="normal"):
    """Apply combination of border, shadow, and subtle blur effects"""
    try:
        # Apply effects in sequence
        # 1. First apply subtle blur
        result = apply_blur_effect(char_img, shape)
        
        # 2. Then apply shadow
        result = apply_shadow_effect(result, shape)
        
        # 3. Finally apply border (lighter for combo)
        # Modify border effect to be more subtle when combined
        border_width = max(3, min(result.size) // 30)  # Thinner border for combo
        new_width = result.width + border_width * 2
        new_height = result.height + border_width * 2
        
        bordered_img = Image.new('RGBA', (new_width, new_height), (0, 0, 0, 0))
        
        # Create subtle border
        if result.mode == 'RGBA':
            # Light border color for combo effect
            border_color = Image.new('RGBA', (new_width, new_height), (255, 255, 255, 100))
            bordered_img = Image.alpha_composite(bordered_img, border_color)
        
        # Paste the character with shadow
        paste_x = border_width
        paste_y = border_width
        if result.mode == 'RGBA':
            bordered_img.paste(result, (paste_x, paste_y), result)
        else:
            bordered_img.paste(result, (paste_x, paste_y))
        
        return bordered_img
        
    except Exception as e:
        print(f"Error in apply_combo_effect: {e}")
        return char_img

def character_mages(image, category=None):
    """
    Add random character icons above the vector, but below the text.
    Supports multiple styles including new half, diagonal, and curve styles.
    """
    try:
        # Get the correct character directory for this category
        character_dir = get_character_dir(category)
        print(f"Looking for character images in: {character_dir}")
        
        # Get character style file from correct location
        character_style_file = os.path.join(get_image_gen_dir(), "character", "character_style.txt")
        
        # Get all character images for this category
        char_images = []
        for ext in ['*.png', '*.jpg', '*.jpeg']:
            found_images = glob.glob(os.path.join(character_dir, ext))
            char_images.extend(found_images)
            print(f"Found {len(found_images)} images with extension {ext}")

        if not char_images:
            print(f"No character images found in {character_dir}")
            return image

        # Select random character image
        character_path = random.choice(char_images)
        print(f"Selected character image: {character_path}")
        char_img = Image.open(character_path).convert("RGBA")

        # Default styles from central configuration
        default_values = get_default_config_values()
        default_style = default_values["character_style"]
        default_styles = default_values["character_styles"]
        
        # Read style from file
        char_style = default_style
        if os.path.exists(character_style_file):
            with open(character_style_file, 'r', encoding='utf-8') as f:
                style = f.read().strip().lower()
                
                # Support legacy styles
                if style in ["left", "center", "right"]:
                    style = f"{style}-normal"
                
                if style in default_styles:
                    char_style = style
                else:
                    print(f"Invalid character style: {style}, using default: {default_style}")
                    char_style = default_style

        # Parse style components
        style_parts = char_style.split('-')
        position = style_parts[0]  # left, center, right
        shape = style_parts[1] if len(style_parts) > 1 else "normal"

        # Handle new special shapes that need full image processing
        if shape in ["half", "diagonal", "curve"]:
            return apply_special_character_style(image, char_img, position, shape)

        # Original processing for standard shapes
        # Resize if too large
        max_char_width = int(image.width * 0.4)
        if char_img.width > max_char_width:
            aspect_ratio = char_img.height / char_img.width
            new_width = max_char_width
            new_height = int(new_width * aspect_ratio)
            char_img = char_img.resize((new_width, new_height), Image.Resampling.LANCZOS)

        # Apply shape transformation for standard shapes
        if shape != "normal":
            mask = create_smooth_mask(char_img.size, shape)
            char_img.putalpha(mask)
            
        # Rotate icon randomly between -10° and +10°
        angle = random.uniform(-10, 10)
        char_img = char_img.rotate(angle, expand=True, resample=Image.Resampling.BICUBIC)
        
        canvas = Image.new('RGBA', image.size, (0, 0, 0, 0))

        # Calculate position
        x_pos = {
            "left": int(image.width * 0.05),
            "center": (image.width - char_img.width) // 2,
            "right": image.width - char_img.width - int(image.width * 0.05)
        }.get(position, (image.width - char_img.width) // 2)

        y_pos = (image.height - char_img.height) // 2
        canvas.paste(char_img, (x_pos, y_pos), char_img)

        # Paste icon onto the image
        base_image = image.convert("RGBA")
        base_image = Image.alpha_composite(base_image, canvas)

        return base_image.convert("RGB")
    
    except Exception as e:
        print(f"Error in character_mages: {e}")
        import traceback
        traceback.print_exc()
        return image

def apply_special_character_style(base_image, char_img, position, shape):
    """Apply special character styles: half, diagonal, curve"""
    try:
        # Convert base image to RGBA for processing
        base_image = base_image.convert("RGBA")
        img_width, img_height = base_image.size
        
        # Target dimensions for character image
        # Height: 100% of image height (450px)
        # Width: 60% of image width (60% of 800px = 480px)
        target_width = int(img_width * 0.6)  # 60% of 800px = 480px
        target_height = img_height  # 100% of 450px
        
        # Resize character image to meet target dimensions
        # Maintain aspect ratio while ensuring area is filled
        char_aspect = char_img.width / char_img.height
        target_aspect = target_width / target_height
        
        if char_aspect > target_aspect:
            # Character is wider, fit to height (crop width if needed)
            new_height = target_height
            new_width = int(target_height * char_aspect)
            # If too wide, limit to target width
            if new_width > target_width:
                new_width = target_width
                new_height = int(target_width / char_aspect)
        else:
            # Character is taller, fit to width (crop height if needed)  
            new_width = target_width
            new_height = int(target_width / char_aspect)
            # If too tall, limit to target height
            if new_height > target_height:
                new_height = target_height
                new_width = int(target_height * char_aspect)
        
        # Resize character image
        char_img_resized = char_img.resize((new_width, new_height), Image.Resampling.LANCZOS)
        
        # Create canvas for character
        char_canvas = Image.new('RGBA', (img_width, img_height), (0, 0, 0, 0))
        
        # Position character image based on style position
        if position == "left":
            char_x = 0  # Position on the left
        else:  # right
            char_x = img_width - new_width  # Position on the right
        
        # Center vertically
        char_y = (img_height - new_height) // 2
        
        # Ensure position is not negative
        char_x = max(0, char_x)
        char_y = max(0, char_y)
        
        # Crop if character image exceeds canvas bounds
        if char_x + new_width > img_width:
            crop_width = img_width - char_x
            char_img_resized = char_img_resized.crop((0, 0, crop_width, new_height))
            new_width = crop_width
            
        if char_y + new_height > img_height:
            crop_height = img_height - char_y
            char_img_resized = char_img_resized.crop((0, 0, new_width, crop_height))
            new_height = crop_height
        
        # Paste character image onto canvas
        char_canvas.paste(char_img_resized, (char_x, char_y), char_img_resized)
        
        # Create appropriate mask based on shape and position
        if shape == "half":
            mask = create_blur_mask((img_width, img_height), "vertical", position, blur_intensity=8)
        elif shape == "diagonal":
            mask = create_blur_mask((img_width, img_height), "diagonal", position, blur_intensity=6)
        elif shape == "curve":
            mask = create_blur_mask((img_width, img_height), "curve", position, blur_intensity=5)
        
        # Apply mask to character canvas
        char_canvas.putalpha(mask)
        
        # Composite character onto base image
        result = Image.alpha_composite(base_image, char_canvas)
        
        return result.convert("RGB")
        
    except Exception as e:
        print(f"Error in apply_special_character_style: {e}")
        import traceback
        traceback.print_exc()
        return base_image

def create_smooth_mask(size, shape="normal", radius_factor=8, antialias=True):
    width, height = size
    scale = 4 if antialias else 1
    big_mask = Image.new('L', (width * scale, height * scale), 0)
    draw = ImageDraw.Draw(big_mask)
    
    if shape == "circle":
        draw.ellipse([0, 0, width * scale - 1, height * scale - 1], fill=255)
    elif shape == "rounded":
        radius = min(width, height) // radius_factor * scale
        draw.rounded_rectangle([0, 0, width * scale - 1, height * scale - 1], radius=radius, fill=255)
    elif shape == "square":
        draw.rectangle([0, 0, width * scale - 1, height * scale - 1], fill=255)
    else:
        draw.rectangle([0, 0, width * scale - 1, height * scale - 1], fill=255)
    
    # Downscale with antialiasing
    if antialias:
        mask = big_mask.resize(size, Image.Resampling.LANCZOS)
    else:
        mask = big_mask
    mask = mask.filter(ImageFilter.GaussianBlur(0.5))
    return mask

def validate_character_structure():
    """Validate character directory structure and images"""
    base_dir = get_base_dir()
    content_path = os.path.join(base_dir, "content")
    
    # Get all categories from content
    categories = []
    try:
        # Add fixed categories
        categories.extend(["profile", "page"])
        
        # Add dynamic categories
        for item in os.listdir(content_path):
            item_path = os.path.join(content_path, item)
            if os.path.isdir(item_path) and item not in ["profile", "page"]:
                categories.append(item)
        
        print("\nValidating character structure...")
        print("Found categories:", categories)
        
        # Check each category
        for category in categories:
            char_dir = get_character_dir(category)
            print(f"\nChecking category: {category}")
            print(f"Character directory: {char_dir}")
            
            # Count images
            image_count = 0
            for ext in ['*.png', '*.jpg', '*.jpeg']:
                files = glob.glob(os.path.join(char_dir, ext))
                image_count += len(files)
            
            if image_count == 0:
                print(f"WARNING: No character images found for category '{category}'")
                print(f"Please add character images to: {char_dir}")
            else:
                print(f"Found {image_count} character images")
                
    except Exception as e:
        print(f"Error validating character structure: {e}")

def get_gradient_colors_from_file():
    """Read gradient colors from file"""
    colors_file = os.path.join(get_image_gen_dir(), "colors", "gradient.txt")
    gradient_pairs = []
    
    try:
        # Read from file
        with open(colors_file, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            
        for line in lines:
            line = line.strip()
            if ',' in line:
                start_color, end_color = line.split(',', 1)
                start_color = start_color.strip()
                end_color = end_color.strip()
                
                # Validate colors
                if re.match(r'^#(?:[0-9a-fA-F]{3}){1,2}$', start_color) and re.match(r'^#(?:[0-9a-fA-F]{3}){1,2}$', end_color):
                    gradient_pairs.append((start_color, end_color))
                else:
                    print(f"Invalid color format in line: {line}")
        
        # If no valid gradients found, use defaults
        if not gradient_pairs:
            print("No valid gradient pairs found, using defaults")
            gradient_pairs = get_default_config_values()["gradient_colors"]
    except Exception as e:
        print(f"Error reading gradient file: {e}")
        import traceback
        traceback.print_exc()
        # Fallback gradient colors if file not found
        gradient_pairs = get_default_config_values()["gradient_colors"]
    
    print(f"Loaded {len(gradient_pairs)} gradient pairs")
    return gradient_pairs

def ensure_gradient_contrast(color_pairs):
    """Make sure the gradient color pairs have sufficient contrast"""
    high_contrast_pairs = []
    
    for start_color, end_color in color_pairs:
        try:
            start_rgb = ImageColor.getrgb(start_color)
            end_rgb = ImageColor.getrgb(end_color)
            
            r_diff = abs(start_rgb[0] - end_rgb[0])
            g_diff = abs(start_rgb[1] - end_rgb[1])
            b_diff = abs(start_rgb[2] - end_rgb[2])
            
            total_diff = r_diff + g_diff + b_diff
            
            if total_diff > 150:
                high_contrast_pairs.append((start_color, end_color))
        except:
            continue
   
    if not high_contrast_pairs:
        high_contrast_pairs = get_default_config_values()["gradient_colors"]
    
    return high_contrast_pairs

def create_gradient_image(size, start_color, end_color, direction='vertical'):
    """Create a gradient image"""
    try:
        print(f"Creating gradient image: {start_color} to {end_color}, direction: {direction}")
        width, height = size
        image = Image.new('RGB', size, start_color)
        draw = ImageDraw.Draw(image)
        
        # Convert hex colors to RGB
        try:
            start_rgb = ImageColor.getrgb(start_color)
            end_rgb = ImageColor.getrgb(end_color)
        except ValueError as e:
            print(f"Color error: {e}, defaulting to blue gradient")
            # Default to blue gradient if colors are invalid
            start_rgb = (52, 152, 219)  # Light blue
            end_rgb = (41, 128, 185)  # Dark blue
        
        # Create gradient
        if direction == 'vertical':
            for y in range(height):
                # Calculate the ratio of the current position
                ratio = y / height
                # Interpolate between start and end colors
                r = int(start_rgb[0] * (1 - ratio) + end_rgb[0] * ratio)
                g = int(start_rgb[1] * (1 - ratio) + end_rgb[1] * ratio)
                b = int(start_rgb[2] * (1 - ratio) + end_rgb[2] * ratio)
                # Draw a line with the calculated color
                draw.line([(0, y), (width, y)], fill=(r, g, b))
        else:  # horizontal
            for x in range(width):
                ratio = x / width
                r = int(start_rgb[0] * (1 - ratio) + end_rgb[0] * ratio)
                g = int(start_rgb[1] * (1 - ratio) + end_rgb[1] * ratio)
                b = int(start_rgb[2] * (1 - ratio) + end_rgb[2] * ratio)
                draw.line([(x, 0), (x, height)], fill=(r, g, b))
        
        print("Gradient created successfully")
        return image
    except Exception as e:
        print(f"Error creating gradient: {e}")
        import traceback
        traceback.print_exc()
        # Return a solid color image as fallback
        return Image.new('RGB', size, "#3498db")

def create_gradient_image_with_vector(size, start_color, end_color, direction='vertical', category=None):
    """Create a gradient image with vector overlay with improved error handling"""
    try:
        # First create gradient
        width, height = size
        image = create_gradient_image(size, start_color, end_color, direction)
        
        # Get vector overlay
        vector_path = load_vector_overlay(category)
        
        if not vector_path:
            print("No vector overlay found, returning gradient only")
            return image  # Return just the gradient if no vector found
        
        try:
            vector_img = Image.open(vector_path).convert('RGBA')
            print(f"Vector overlay loaded: {vector_path}")
            
            # Resize to match the background
            vector_img = vector_img.resize(size, Image.Resampling.LANCZOS)
            
            # Adjust opacity based on image brightness
            start_rgb = ImageColor.getrgb(start_color)
            end_rgb = ImageColor.getrgb(end_color)
            avg_brightness = (sum(start_rgb) + sum(end_rgb)) / 6
            
            # Adjust opacity based on brightness
            if avg_brightness > 200:  # Very light background
                opacity = 0.1
            elif avg_brightness > 150:  # Light background
                opacity = 0.15
            elif avg_brightness > 100:  # Medium background
                opacity = 0.2
            else:  # Dark background
                opacity = 0.25
            
            # Apply the opacity
            if 'A' in vector_img.getbands():
                # If the image has an alpha channel
                alpha = vector_img.split()[3]
                alpha = ImageEnhance.Brightness(alpha).enhance(opacity)
                vector_img.putalpha(alpha)
            else:
                # Create a new alpha channel
                alpha = Image.new('L', size, int(255 * opacity))
                vector_img.putalpha(alpha)
            
            # Composite with gradient (Layer 1: Gradient, Layer 2: Vector)
            image_rgba = image.convert('RGBA')
            result = Image.alpha_composite(image_rgba, vector_img)
            
            # Add character overlay (Layer 3: Character)
            result = character_mages(result, category)
            
            print("Vector overlay applied successfully")
            return result.convert('RGB')  # Convert to RGB for JPEG compatibility
        except Exception as e:
            print(f"Error adding vector overlay: {e}")
            import traceback
            traceback.print_exc()
            return image  # Return just gradient on error
    except Exception as e:
        print(f"Error in create_gradient_image_with_vector: {e}")
        import traceback
        traceback.print_exc()
        # Return solid color as fallback
        return Image.new('RGB', size, "#3498db")

def get_text_alignment_from_file():
    """Read text alignment preferences from file"""
    alignment_file = os.path.join(get_repo_path(), "image-generator", "fonts", "text_style.txt")
    default_values = get_default_config_values()
    default_alignment = default_values["text_styles"]
    
    try:
        # Read from file
        with open(alignment_file, 'r', encoding='utf-8') as file:
            alignment = file.read().strip().lower()
        
        # Alignment validation
        valid_alignments = ["left", "center", "right"]
        if alignment not in valid_alignments:
            print(f"Invalid alignment: {alignment}, use defaults: {default_alignment}")
            alignment = default_alignment
    except Exception as e:
        print(f"Error reading alignment preferences file: {e}")
        alignment = default_alignment
    
    print(f"Using text alignment: {alignment}")
    return alignment

def fit_text_to_width(draw, text, font_path, max_width, initial_size, min_size=10, font_style="normal"):
    """Adjust font size to fit text to available width with non-Latin script support and font style"""
    size = initial_size
    
    try:
        # Try to create styled font
        font = create_styled_font(font_path, size, font_style)
    except OSError:
        # Fallback to a system font that supports wide character ranges
        try:
            # Try to find a universal font like Arial Unicode MS, Noto Sans, or DejaVu Sans
            system_fonts = [
                "Arial Unicode MS", "NotoSansCJK-Regular.ttc", "NotoSansArabic-Regular.ttf",
                "NotoSansThai-Regular.ttf", "DejaVuSans.ttf"
            ]
            
            for sys_font in system_fonts:
                try:
                    font = ImageFont.truetype(sys_font, size)
                    font_path = sys_font  # Update font_path for future use
                    break
                except OSError:
                    continue
            else:
                # If no suitable font found, use default
                font = ImageFont.load_default()
        except:
            font = ImageFont.load_default()
    
    # Get text width using getbbox for better handling of non-Latin scripts
    # This is more reliable than textlength for CJK and RTL languages
    try:
        # For newer Pillow versions
        bbox = font.getbbox(text)
        text_width = bbox[2] - bbox[0]
    except AttributeError:
        # Fallback for older Pillow versions
        text_width = draw.textlength(text, font=font)
    
    # Reduce font size until text fits
    while text_width > max_width and size > min_size:
        size -= 1
        font = create_styled_font(font_path, size, font_style)
        try:
            bbox = font.getbbox(text)
            text_width = bbox[2] - bbox[0]
        except AttributeError:
            text_width = draw.textlength(text, font=font)
    
    # If text is too long even at minimum font size, truncate it
    if text_width > max_width:
        # For non-Latin scripts, we need to be careful about truncation
        # as character boundaries can be complex
        truncate_ratio = max_width / text_width
        truncate_length = int(len(text) * truncate_ratio) - 3  # -3 for "..."
        text = text[:truncate_length] + "..."
    
    return font, text

def create_multiline_text(draw, text, font, max_width, alignment="center"):
    """Split text into multiple lines with 45% width limit"""
    max_text_width = int(max_width * 0.45)  # 45% dari lebar gambar
    words = text.split()
    lines = []
    current_line = []
    
    for word in words:
        # Try adding the word to current line
        test_line = ' '.join(current_line + [word])
        
        # Get text width
        try:
            bbox = font.getbbox(test_line)
            text_width = bbox[2] - bbox[0]
        except AttributeError:
            text_width = draw.textlength(test_line, font=font)
        
        if text_width <= max_text_width:
            current_line.append(word)
        else:
            # If current line has words, complete it
            if current_line:
                lines.append(' '.join(current_line))
                current_line = [word]
            else:
                # If single word is too long, force add it
                lines.append(word)
                current_line = []
    
    # Add remaining line if any
    if current_line:
        lines.append(' '.join(current_line))
    
    return lines, alignment

def adjust_font_size_for_multiline(draw, text, font_path, max_width, initial_size=38):
    """Adjust font size for multiline text to fit width constraint"""
    size = initial_size
    while size > 12:  # Minimum font size
        font = create_styled_font(font_path, size)
        lines, _ = create_multiline_text(draw, text, font, max_width)
        
        # Check if any line exceeds 45% width
        max_line_width = max(draw.textlength(line, font=font) for line in lines)
        if max_line_width <= max_width * 0.45:
            return font, lines
            
        size -= 1
    
    # Return smallest acceptable font if we get here
    font = create_styled_font(font_path, 12)
    return font, create_multiline_text(draw, text, font, max_width)[0]

def load_vector_overlay(category_name=None):
    """Load vector overlay image"""
    vector_dir = os.path.join(get_image_gen_dir(), "vector")
    
    # Supported vector file types
    supported_extensions = ['.jpg', '.png', '.svg', '.gif']
    vector_files = []
    
    # Collect all vector files
    for ext in supported_extensions:
        vector_files.extend(glob.glob(os.path.join(vector_dir, f"*{ext}")))
    
    # If category-specific vector exists, prioritize it
    if category_name:
        category_vectors = [v for v in vector_files if category_name.lower() in os.path.basename(v).lower()]
        if category_vectors:
            return random.choice(category_vectors)
    
    # If no vectors found or no category match
    if not vector_files:
        print("No vector files found for overlay.")
        return None
        
    # Return a random vector file
    return random.choice(vector_files)

def get_text_style_from_file():
    """Read text style preferences from file"""
    # Get text style file path
    style_file = os.path.join(get_image_gen_dir(), "fonts", "text_style.txt")
    default_style = "center-normal"
    
    try:
        if not os.path.exists(style_file):
            # Create default text style file
            os.makedirs(os.path.dirname(style_file), exist_ok=True)
            with open(style_file, 'w', encoding='utf-8') as f:
                f.write(default_style)
            return "center", "normal"
            
        with open(style_file, 'r', encoding='utf-8') as f:
            text_style = f.read().strip().lower()
            
            # Valid text styles
            valid_styles = [
                "left-normal", "left-italic", "left-oblique", "left-bold", "left-bold-italic", "left-bold-oblique",
                "right-normal", "right-italic", "right-oblique", "right-bold", "right-bold-italic", "right-bold-oblique",
                "center-normal", "center-italic", "center-oblique", "center-bold", "center-bold-italic", "center-bold-oblique",
                "top-left-normal", "top-left-italic", "top-left-oblique", "top-left-bold", "top-left-bold-italic", "top-left-bold-oblique",
                "top-right-normal", "top-right-italic", "top-right-oblique", "top-right-bold", "top-right-bold-italic", "top-right-bold-oblique",
                "bottom-left-normal", "bottom-left-italic", "bottom-left-oblique", "bottom-left-bold", "bottom-left-bold-italic", "bottom-left-bold-oblique",
                "bottom-right-normal", "bottom-right-italic", "bottom-right-oblique", "bottom-right-bold", "bottom-right-bold-italic", "bottom-right-bold-oblique"
            ]
            
            if text_style not in valid_styles:
                print(f"Invalid text style: {text_style}, using default: {default_style}")
                return "center", "normal"
            
            # Parse style components
            parts = text_style.split('-')
            
            if len(parts) == 2:
                # Format: position-style (e.g., "left-normal", "center-bold")
                position = parts[0]
                font_style = parts[1]
            elif len(parts) == 3:
                # Format: compound-position-style (e.g., "top-left-normal", "bottom-right-italic")
                position = f"{parts[0]}-{parts[1]}"
                font_style = parts[2]
            else:
                print(f"Invalid style format: {text_style}, using default")
                return "center", "normal"
            
            print(f"Using text style - Position: {position}, Font Style: {font_style}")
            return position, font_style
            
    except Exception as e:
        print(f"Error reading text style: {e}")
        return "center", "normal"

def position_text(image_size, text_size, position):
    """Calculate text position based on style"""
    margin = 30  # Margin from edges
    
    # Calculate positions
    x, y = 0, 0
    
    if position == "left":
        x = margin
        y = (image_size[1] - text_size[1]) // 2
    elif position == "right":
        x = image_size[0] - text_size[0] - margin
        y = (image_size[1] - text_size[1]) // 2
    elif position == "center":
        x = (image_size[0] - text_size[0]) // 2
        y = (image_size[1] - text_size[1]) // 2
    elif position == "top-left":
        x = margin
        y = margin
    elif position == "top-right":
        x = image_size[0] - text_size[0] - margin
        y = margin
    elif position == "bottom-left":
        x = margin
        y = image_size[1] - text_size[1] - margin
    elif position == "bottom-right":
        x = image_size[0] - text_size[0] - margin
        y = image_size[1] - text_size[1] - margin
    else:
        # Default to center if position not found
        x = (image_size[0] - text_size[0]) // 2
        y = (image_size[1] - text_size[1]) // 2
    
    # Apply margin constraints
    x = max(margin, min(x, image_size[0] - text_size[0] - margin))
    y = max(margin, min(y, image_size[1] - text_size[1] - margin))
    
    print(f"Text position calculated - X: {x}, Y: {y}")
    return (x, y)

def get_block_position(image_size, block_size, position):
    """Calculate the starting (x, y) for the whole text block based on style position"""
    margin = 30  # px
    x, y = 0, 0
    
    if position == "top-left":
        x = margin
        y = margin
    elif position == "top-right":
        x = image_size[0] - block_size[0] - margin
        y = margin
    elif position == "bottom-left":
        x = margin
        y = image_size[1] - block_size[1] - margin
    elif position == "bottom-right":
        x = image_size[0] - block_size[0] - margin
        y = image_size[1] - block_size[1] - margin
    elif position == "left":
        x = margin
        y = (image_size[1] - block_size[1]) // 2
    elif position == "right":
        x = image_size[0] - block_size[0] - margin
        y = (image_size[1] - block_size[1]) // 2
    elif position == "center":
        x = (image_size[0] - block_size[0]) // 2
        y = (image_size[1] - block_size[1]) // 2
    else:
        # fallback to center
        x = (image_size[0] - block_size[0]) // 2
        y = (image_size[1] - block_size[1]) // 2
    
    return x, y

def create_image_with_text(title, output_path, bg_source, bg_type, font_path, font_size, image_size, text_color=None, watermark_info=None, category=None):
    try:
        # Get text style preferences
        position, font_style = get_text_style_from_file()
        print(f"Using text position: {position}, font style: {font_style}")
        
        # Get font size from file
        custom_font_size = get_font_size_from_file()
        if custom_font_size != font_size:
            print(f"Using custom font size: {custom_font_size}")
            font_size = custom_font_size

        img = None
        max_width = int(image_size[0] * 0.8)  # Use 80% of image width for text
        max_height = int(image_size[1] * 0.8)  # Use 80% of image height for text
        
        # Create background
        if bg_type == "solid":
            img = Image.new('RGB', image_size, bg_source)
        elif bg_type == "gradient":
            start_color, end_color = bg_source
            direction = random.choice(['vertical', 'horizontal'])
            img = create_gradient_image_with_vector(image_size, start_color, end_color, direction, category)
        else:  # bg_type == "image"
            bg_img = Image.open(bg_source)
            # Resize background image to fit the desired dimensions
            bg_img = bg_img.resize(image_size)
            img = bg_img.copy()
            
            # Add semi-transparent overlay for better text visibility
            overlay = Image.new('RGBA', image_size, (0, 0, 0, 128))  # Black with 50% opacity
            img = Image.alpha_composite(img.convert('RGBA'), overlay)
            img = img.convert('RGB')  # Convert back to RGB
        
        draw = ImageDraw.Draw(img)
        
        # Create font with appropriate style
        font = create_styled_font(font_path, font_size, font_style)
        
        # Split text into multiple lines
        lines, _ = create_multiline_text(draw, title, font, max_width, "left")  # Always use left alignment for line splitting
        
        # Calculate total text height
        line_spacing = font_size * 0.2
        line_height = font_size + line_spacing
        total_height = line_height * len(lines)
        max_line_width = max(draw.textlength(line, font=font) for line in lines)
        block_size = (max_line_width, total_height)
        
        # Calculate block starting position
        block_x, block_y = get_block_position(image_size, block_size, position)
        
        # Determine text and shadow colors based on background
        if text_color:
            # Use user-specified text color
            main_text_color = text_color
            shadow_color = "black" if is_light_color(text_color) else "white"
        else:
            if bg_type == "image":
                main_text_color = "white"
                shadow_color = "black"
            elif bg_type == "gradient":
                # For gradient, use contrasting colors
                start_rgb = ImageColor.getrgb(bg_source[0])
                end_rgb = ImageColor.getrgb(bg_source[1])
                avg_brightness = (sum(start_rgb) + sum(end_rgb)) / 6  # Average brightness of gradient
                main_text_color = "black" if avg_brightness > 128 else "white"
                shadow_color = "white" if avg_brightness > 128 else "black"
            else:  # solid color
                bg_rgb = ImageColor.getrgb(bg_source)
                brightness = sum(bg_rgb) / 3
                main_text_color = "black" if brightness > 128 else "white"
                shadow_color = "white" if brightness > 128 else "black"
        
        # Add text shadow for better visibility
        shadow_offset = max(1, font_size // 20)
        
        # Draw each line of text with proper alignment within the block
        for i, line in enumerate(lines):
            text_width = draw.textlength(line, font=font)
            
            # Calculate x position based on position style
            if position in ["left", "top-left", "bottom-left"]:
                x_position = block_x  # Left aligned within block
            elif position in ["right", "top-right", "bottom-right"]:
                x_position = block_x + (block_size[0] - text_width)  # Right aligned within block
            else:  # center and other positions
                x_position = block_x + (block_size[0] - text_width) // 2  # Center aligned within block
                
            current_y = block_y + i * line_height
        
            # Draw text shadow
            draw.text((x_position + shadow_offset, current_y + shadow_offset), line, font=font, fill=shadow_color)
            # Draw main text
            draw.text((x_position, current_y), line, font=font, fill=main_text_color)
            
        # Add watermark if specified
        if watermark_info:
            watermark_type, watermark_params = watermark_info
            if len(watermark_params) == 3:  # New format with size_percentage
                watermark_source, opacity, size_percentage = watermark_params
                img = add_watermark(img.convert('RGBA'), watermark_source, watermark_type, opacity, size_percentage)
            else:  # Support for old format
                watermark_source, opacity = watermark_params
                img = add_watermark(img.convert('RGBA'), watermark_source, watermark_type, opacity)
        
        # Convert to RGB if necessary (for JPEG format)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Save the image in JPEG format with quality=95
        img.save(output_path, format='JPEG', quality=95, optimize=True)
        
        # Optimize the image for GitHub
        optimize_image_for_github(output_path)
        return True
        
    except Exception as e:
        print(f"Error creating image: {e}")
        import traceback
        traceback.print_exc()
        return False

def create_styled_font(font_path, font_size, style="normal"):
    """Create font with specified style"""
    try:
        # Load the font
        if font_path is None:
            # Fallback to default font
            if "bold" in style.lower():
                # Try to find a bold system font
                try:
                    return ImageFont.truetype("Arial Bold", font_size)
                except:
                    return ImageFont.load_default()
            else:
                return ImageFont.load_default()
                
        # Check if font exists
        if not os.path.exists(font_path):
            print(f"Font not found: {font_path}")
            return ImageFont.load_default()
            
        # Get font directory and base name
        base_dir = os.path.dirname(font_path)
        base_name = os.path.basename(font_path)
        name_without_ext = os.path.splitext(base_name)[0]
        
        # Remove common suffixes to get base font name
        base_font_name = name_without_ext
        for suffix in ['-Regular', 'Regular', '-Normal', 'Normal']:
            if base_font_name.endswith(suffix):
                base_font_name = base_font_name[:-len(suffix)]
                break
        
        # Create font with style
        font = None
        
        if style == "normal":
            font = ImageFont.truetype(font_path, font_size)
            
        elif style in ["italic", "oblique"]:
            # Try to find italic/oblique variant
            italic_patterns = [
                f"{base_font_name}-Italic.ttf", 
                f"{base_font_name}Italic.ttf",
                f"{base_font_name}-It.ttf",
                f"{base_font_name}-Oblique.ttf",
                f"{base_font_name}Oblique.ttf",
                f"{name_without_ext}-Italic.ttf",
                f"{name_without_ext}Italic.ttf"
            ]
            
            italic_font_path = None
            for pattern in italic_patterns:
                potential_path = os.path.join(base_dir, pattern)
                if os.path.exists(potential_path):
                    italic_font_path = potential_path
                    break
            
            if italic_font_path:
                font = ImageFont.truetype(italic_font_path, font_size)
                print(f"Using italic font: {italic_font_path}")
            else:
                print(f"No italic variant found for {font_path}, using regular font")
                font = ImageFont.truetype(font_path, font_size)
        
        elif style == "bold":
            # Try to find bold variant
            bold_patterns = [
                f"{base_font_name}-Bold.ttf", 
                f"{base_font_name}Bold.ttf",
                f"{base_font_name}-Bd.ttf",
                f"{name_without_ext}-Bold.ttf",
                f"{name_without_ext}Bold.ttf"
            ]
            
            bold_font_path = None
            for pattern in bold_patterns:
                potential_path = os.path.join(base_dir, pattern)
                if os.path.exists(potential_path):
                    bold_font_path = potential_path
                    break
            
            if bold_font_path:
                font = ImageFont.truetype(bold_font_path, font_size)
                print(f"Using bold font: {bold_font_path}")
            else:
                print(f"No bold variant found for {font_path}, using regular font")
                font = ImageFont.truetype(font_path, font_size)
                
        elif style in ["bold-italic", "bold-oblique"]:
            # Try to find bold-italic variant
            bold_italic_patterns = [
                f"{base_font_name}-BoldItalic.ttf", 
                f"{base_font_name}BoldItalic.ttf",
                f"{base_font_name}-BdIt.ttf",
                f"{base_font_name}-BoldOblique.ttf",
                f"{base_font_name}BoldOblique.ttf",
                f"{name_without_ext}-BoldItalic.ttf",
                f"{name_without_ext}BoldItalic.ttf"
            ]
            
            bold_italic_font_path = None
            for pattern in bold_italic_patterns:
                potential_path = os.path.join(base_dir, pattern)
                if os.path.exists(potential_path):
                    bold_italic_font_path = potential_path
                    break
            
            if bold_italic_font_path:
                font = ImageFont.truetype(bold_italic_font_path, font_size)
                print(f"Using bold-italic font: {bold_italic_font_path}")
            else:
                # Try to find bold variant as fallback
                bold_patterns = [
                    f"{base_font_name}-Bold.ttf", 
                    f"{base_font_name}Bold.ttf",
                    f"{base_font_name}-Bd.ttf"
                ]
                
                bold_font_path = None
                for pattern in bold_patterns:
                    potential_path = os.path.join(base_dir, pattern)
                    if os.path.exists(potential_path):
                        bold_font_path = potential_path
                        break
                
                if bold_font_path:
                    font = ImageFont.truetype(bold_font_path, font_size)
                    print(f"Bold-italic not found, using bold font: {bold_font_path}")
                else:
                    print(f"No bold-italic or bold variant found for {font_path}, using regular font")
                    font = ImageFont.truetype(font_path, font_size)
        
        else:
            # Default to normal if style not recognized
            print(f"Unknown font style: {style}, using normal")
            font = ImageFont.truetype(font_path, font_size)
            
        return font
        
    except Exception as e:
        print(f"Error creating styled font: {e}")
        # Return default font as fallback
        return ImageFont.load_default()

def add_watermark(img, watermark_source, watermark_type='text', opacity=0.7, size_percentage=0.1):
    """Add watermark to image at bottom right corner with optimized size"""
    try:
        # Pastikan img dalam mode RGBA
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
        
        # Create a copy of the image
        result = img.copy()
        
        # Debug info
        print(f"Attempting to add watermark: {watermark_source}, type: {watermark_type}")
        
        if watermark_type == 'text':
            # Create a new transparent image for the watermark
            watermark = Image.new('RGBA', result.size, (0, 0, 0, 0))
            draw = ImageDraw.Draw(watermark)
            
            # Use a smaller font size relative to the image
            font_size = max(10, int(min(result.size) / 40))
            try:
                # Try to use a common font
                font = ImageFont.truetype("arial.ttf", font_size)
            except Exception as e:
                print(f"Font error: {e}, falling back to default")
                # Fallback to default
                font = ImageFont.load_default()
            
            # Calculate text size and position
            try:
                bbox = font.getbbox(watermark_source)
                text_width = bbox[2] - bbox[0]
                text_height = bbox[3] - bbox[1]
            except AttributeError:
                text_width = draw.textlength(watermark_source, font=font)
                text_height = font_size
            
            # Position at bottom right with 8px padding
            position = (result.width - text_width - 8, result.height - text_height - 8)
            
            # Draw the text with a subtle shadow for better visibility
            shadow_position = (position[0] + 1, position[1] + 1)
            draw.text(shadow_position, watermark_source, font=font, fill=(0, 0, 0, int(255 * opacity)))
            draw.text(position, watermark_source, font=font, fill=(255, 255, 255, int(255 * opacity)))
            
            # Composite the watermark onto the original image
            result = Image.alpha_composite(result, watermark)
            
        else:  # watermark_type == 'image'
            try:
                # Verify watermark file exists
                if not os.path.exists(watermark_source):
                    print(f"Watermark image not found: {watermark_source}")
                    # Check in current directory and alternative paths
                    repo_path = get_repo_path()
                    alt_paths = [
                        os.path.join(repo_path, "watermark.png"),
                        os.path.join(repo_path, "image-generator", "watermark.png")
                    ]
                    
                    for alt_path in alt_paths:
                        if os.path.exists(alt_path):
                            print(f"Using alternative watermark path: {alt_path}")
                            watermark_source = alt_path
                            break
                    else:
                        raise FileNotFoundError(f"No watermark found in alternative paths")
                
                # Open watermark image
                watermark_img = Image.open(watermark_source).convert('RGBA')
                print(f"Watermark image opened successfully: {watermark_source}")
                
                # Resize watermark to smaller percentage
                max_width = int(result.width * size_percentage)
                max_height = int(result.height * size_percentage)
                
                # Keep aspect ratio
                watermark_ratio = watermark_img.width / watermark_img.height
                
                if watermark_img.width > max_width:
                    new_width = max_width
                    new_height = int(new_width / watermark_ratio)
                else:
                    new_width = watermark_img.width
                    new_height = watermark_img.height
                
                if new_height > max_height:
                    new_height = max_height
                    new_width = int(new_height * watermark_ratio)
                
                watermark_img = watermark_img.resize((new_width, new_height), Image.Resampling.LANCZOS)
                
                # Apply opacity to the watermark
                alpha = watermark_img.split()[3]
                alpha = ImageEnhance.Brightness(alpha).enhance(opacity)
                watermark_img.putalpha(alpha)
                
                # Calculate position (bottom right with 8px padding)
                position = (result.width - watermark_img.width - 8, 
                           result.height - watermark_img.height - 8)
                
                # Create a temporary composite image
                temp_img = Image.new('RGBA', result.size, (0, 0, 0, 0))
                temp_img.paste(watermark_img, position, watermark_img)
                
                # Paste the watermark onto the original image
                result = Image.alpha_composite(result, temp_img)
                print("Watermark applied successfully")
                
            except Exception as e:
                print(f"Error processing watermark image: {e}")
                import traceback
                traceback.print_exc()
                return img
        
        return result.convert('RGB')  # Convert back to RGB for saving
    except Exception as e:
        print(f"Error adding watermark: {e}")
        import traceback
        traceback.print_exc()
        return img  # Return original image if there's an error

def optimize_image_for_github(img_path, quality=95, max_size=(800, 450)):
    """Optimize image file size for faster GitHub processing - Updated for JPEG format"""
    try:
        with Image.open(img_path) as img:
            # Resize if image is too large (though it should already be 800x450)
            if img.width > max_size[0] or img.height > max_size[1]:
                img.thumbnail(max_size, Image.Resampling.LANCZOS)
            
            # Convert to RGB if necessary (required for JPEG)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Save with JPEG format and quality=95
            img.save(img_path, format='JPEG', quality=quality, optimize=True)
            
            return True
    except Exception as e:
        print(f"Error optimizing image {img_path}: {e}")
        return False
   
def is_light_color(color):
    """Check if a color is light or dark"""
    try:
        rgb = ImageColor.getrgb(color)
        brightness = sum(rgb) / 3
        return brightness > 128
    except:
        return False

def insert_image_link_in_md(file_path, image_link, position_type, keyword=None):
    try:
        # Extract image path from image link
        # Pattern: ![title](/images/category/filename.png)
        image_path_match = re.search(r'!\[.*?\]\((.*?)\)', image_link)
        if image_path_match:
            image_path = image_path_match.group(1)
        else:
            print(f"Cannot extract image path from link: {image_link}")
            return False
        
        # Read file line by line
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        
        # Find frontmatter boundary lines
        frontmatter_start_idx = -1
        frontmatter_end_idx = -1
        
        for i, line in enumerate(lines):
            if line.strip() == '---':
                if frontmatter_start_idx == -1:
                    frontmatter_start_idx = i
                else:
                    frontmatter_end_idx = i
                    break
        
        if frontmatter_start_idx == -1 or frontmatter_end_idx == -1:
            print("Unable to find frontmatter boundary")
            return False
        
        # Create clean frontmatter without existing featuredImage tags
        clean_frontmatter = []
        for i in range(frontmatter_start_idx, frontmatter_end_idx + 1):
            line = lines[i].strip()
            if not line.startswith('featuredImage:') and not line.startswith('featuredImagePreview:') and line != '---':
                clean_frontmatter.append(line)
        
        # Build new frontmatter
        new_frontmatter = ['---']
        new_frontmatter.extend(clean_frontmatter)
        new_frontmatter.append(f'featuredImage: "{image_path}"')
        new_frontmatter.append(f'featuredImagePreview: "{image_path}"')
        new_frontmatter.append('---')
        
        # Build content after frontmatter
        content_after_frontmatter = []
        if frontmatter_end_idx + 1 < len(lines):
            content_after_frontmatter = lines[frontmatter_end_idx + 1:]
        
        # Insert image based on position
        if position_type == 1:  # At the beginning of article (after frontmatter)
            # Add a blank line after frontmatter, then add the image, then another blank line
            new_content_after_frontmatter = ['\n', image_link + '\n', '\n']
            new_content_after_frontmatter.extend(content_after_frontmatter)
            content_after_frontmatter = new_content_after_frontmatter
        
        elif position_type == 2:  # At custom position based on keyword
            if keyword:
                # Find the line containing the keyword
                keyword_found = False
                for i, line in enumerate(content_after_frontmatter):
                    if keyword in line:
                        # Insert after this line
                        content_after_frontmatter.insert(i + 1, '\n')
                        content_after_frontmatter.insert(i + 2, image_link + '\n')
                        content_after_frontmatter.insert(i + 3, '\n')
                        keyword_found = True
                        break
                
                if not keyword_found:
                    # If keyword not found, insert at the beginning
                    new_content_after_frontmatter = ['\n', image_link + '\n', '\n']
                    new_content_after_frontmatter.extend(content_after_frontmatter)
                    content_after_frontmatter = new_content_after_frontmatter
            else:
                # No keyword provided, insert at the beginning
                new_content_after_frontmatter = ['\n', image_link + '\n', '\n']
                new_content_after_frontmatter.extend(content_after_frontmatter)
                content_after_frontmatter = new_content_after_frontmatter
        
        # Combine new frontmatter and content
        result = []
        result.extend(new_frontmatter)
        result.extend(content_after_frontmatter)
        
        # Write back to file
        with open(file_path, 'w', encoding='utf-8') as file:
            # Make sure each line ends with a newline
            file.writelines([line if line.endswith('\n') else line + '\n' for line in result])
        
        return True
    except Exception as e:
        print(f"Error updating markdown file {file_path}: {e}")
        return False

def clean_generated_images(project_name, category, md_files):
    """Remove image links from markdown files and delete generated images"""
    images_dir = Path(f"C:\\Hugo\\projects\\{project_name}\\static\\images\\{category}")
    
    # Remove image links from markdown files
    for md_file in md_files:
        try:
            with open(md_file, 'r', encoding='utf-8') as file:
                content = file.read()
            
            # Remove image links
            # Pattern matches ![any text](/images/category/any-file.png)
            pattern = r'!\[.*?\]\(/images/' + re.escape(category) + r'/.*?\)'
            new_content = re.sub(pattern, '', content)
            new_content = re.sub(r'\n\n\n+', '\n\n', new_content)  # Clean up extra newlines
            
            # Clear featuredImage and featuredImagePreview in frontmatter
            new_content = re.sub(r'featuredImage:.*?\n', 'featuredImage: ""\n', new_content)
            new_content = re.sub(r'featuredImagePreview:.*?\n', 'featuredImagePreview: ""\n', new_content)
            
            with open(md_file, 'w', encoding='utf-8') as file:
                file.write(new_content)
                
        except Exception as e:
            print(f"Error cleaning file {md_file}: {e}")
    
    # Delete image files
    if images_dir.exists():
        for img_file in images_dir.glob("*.png"):
            try:
                os.remove(img_file)
            except Exception as e:
                print(f"Error removing image {img_file}: {e}")
    
    print(f"All images and links have been removed from {len(md_files)} article.")

def get_image_backgrounds_from_folder(category):
    """Get background images from a folder automatically based on category"""
    folder_path = f"C:\\Hugo\\image-generator\\images\\{category}"
    
    if not os.path.isdir(folder_path):
        print(f"Folder not found: {folder_path}")
        print("Create folders...")
        try:
            os.makedirs(folder_path, exist_ok=True)
            print(f"Folder created successfully. Please add images to: {folder_path}")
            print("Then run the program again.")
            sys.exit(1)
        except Exception as e:
            print(f"Error creating folder: {e}")
            sys.exit(1)
    
    # Get all image files from the folder
    image_files = []
    for ext in ['*.png', '*.jpg', '*.jpeg']:
        image_files.extend(glob.glob(os.path.join(folder_path, ext)))
    
    if len(image_files) < 3:
        print(f"The folder must contain at least 3 image files. Found: {len(image_files)}")
        print(f"Please add more images to: {folder_path}")
        sys.exit(1)
    
    print(f"Found {len(image_files)} images in the folder: {folder_path}")
    return image_files

def get_random_font():
    """Get random font from fonts directory"""
    fonts_dir = os.path.join(get_image_gen_dir(), "fonts")
    
    # Create fonts directory if it doesn't exist
    os.makedirs(fonts_dir, exist_ok=True)
    
    # Check for font files
    font_extensions = ['*.ttf', '*.otf']
    font_files = []
    
    for ext in font_extensions:
        font_files.extend(glob.glob(os.path.join(fonts_dir, ext)))
    
    # If fonts found, return a random one
    if font_files:
        return random.choice(font_files)
    
    # Otherwise try to find system fonts
    system_fonts = []
    
    # Check common font locations based on OS
    if platform.system() == 'Windows':
        font_dirs = [os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Fonts')]
    elif platform.system() == 'Darwin':  # macOS
        font_dirs = ['/Library/Fonts', '/System/Library/Fonts', os.path.expanduser('~/Library/Fonts')]
    else:  # Linux/Unix
        font_dirs = ['/usr/share/fonts', '/usr/local/share/fonts', os.path.expanduser('~/.fonts')]
    
    # Look for fonts in system directories
    for font_dir in font_dirs:
        if os.path.exists(font_dir):
            for ext in font_extensions:
                system_fonts.extend(glob.glob(os.path.join(font_dir, ext)))
                system_fonts.extend(glob.glob(os.path.join(font_dir, '**', ext), recursive=True))
    
    # Common fallback fonts to check for
    common_fonts = ['Arial.ttf', 'Verdana.ttf', 'TimesNewRoman.ttf', 'DejaVuSans.ttf', 'NotoSans-Regular.ttf']
    
    for font_dir in font_dirs:
        for font in common_fonts:
            font_path = os.path.join(font_dir, font)
            if os.path.exists(font_path):
                return font_path
    
    # If still no fonts found, check if PIL has default font access
    try:
        # This will raise exception if no default font available
        ImageFont.load_default()
        return None  # Return None to indicate using default font
    except:
        print("No fonts found, and PIL default font not available")
        return None

def check_image_exists_for_article(md_file, category):
    """Check if image file exists for the article based on title and verify if it's valid"""
    try:
        title = extract_title_from_md(md_file)
        safe_filename = sanitize_filename(title)
        
        # Check for both PNG and JPG extensions
        image_extensions = ['.jpg', '.jpeg', '.png']
        static_path = get_static_category_path(category)
        
        for ext in image_extensions:
            image_filename = f"{safe_filename}{ext}"
            image_path = os.path.join(static_path, image_filename)
            
            if os.path.exists(image_path):
                # Verify image is valid and not corrupted
                try:
                    with Image.open(image_path) as img:
                        img.verify()
                    return True, image_path, image_filename
                except Exception as e:
                    print(f"Found corrupted image {image_path}: {e}")
                    continue
                    
        return False, None, None
    except Exception as e:
        print(f"Error checking image existence: {e}")
        return False, None, None

def has_image_link_in_markdown(md_file, category, image_filename):
    """Check if markdown file already has the image link"""
    try:
        with open(md_file, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Check for the specific image link
        image_link_pattern = f'!\[.*?\]\(/images/{re.escape(category)}/{re.escape(image_filename)}\)'
        return bool(re.search(image_link_pattern, content))
    except Exception as e:
        print(f"Error checking image link in markdown: {e}")
        return False

def generate_images_for_articles():
    """Generate images for articles without featuredImage - optimized version"""
    # Get content path
    content_path = get_content_dir()
    
    # Validate content directory
    if not os.path.exists(content_path):
        print(f"Content directory not found: {content_path}")
        return
    
    # Scan for categories
    categories = []
    try:
        # Add fixed categories
        categories.extend(["profile", "page"])
        
        # Add dynamic categories (niche folders)
        for item in os.listdir(content_path):
            item_path = os.path.join(content_path, item)
            if os.path.isdir(item_path) and item not in ["profile", "page"]:
                categories.append(item)
        
        print(f"Found categories: {categories}")
        
    except Exception as e:
        print(f"Error scanning categories: {e}")
        return

    # Process each category
    for category in categories:
        try:
            # Ensure directories exist
            static_path = get_static_category_path(category)
            char_path = get_character_dir(category)
            
            os.makedirs(static_path, exist_ok=True)
            os.makedirs(char_path, exist_ok=True)
            
            print(f"\nProcessing category: {category}")
            print(f"Static path: {static_path}")
            print(f"Character path: {char_path}")
            
            # Get articles without images
            articles_without_images = get_articles_without_images("", category)
            
            if not articles_without_images:
                print(f"No articles without images in '{category}'")
                continue

            # Get character images for category 
            character_dir = get_character_dir(category)
            if not os.path.exists(character_dir):
                os.makedirs(character_dir, exist_ok=True)
            
            # Get gradient colors
            gradient_pairs = get_gradient_colors_from_file()
            
            # Get random fonts
            font_path = get_random_font()
            if not font_path:
                print("Unable to find font. Process terminated.")
                continue
            
            # Set default parameters
            font_size = 38
            font_color = "#ffffff"
            image_size = (600, 400)
            
            # Set up a watermark
            watermark_path = os.path.join(get_repo_path(), "image-generator", "watermark", "watermark.png")
            watermark_info = ("image", (watermark_path, 0.8, 0.2)) if os.path.exists(watermark_path) else None
            
            success_count = 0
            skip_count = 0
            
            for md_file in articles_without_images:
                title = extract_title_from_md(md_file)
                safe_filename = sanitize_filename(title)
                image_filename = f"{safe_filename}.png"
                
                # Check if image already exists
                image_exists, image_path, _ = check_image_exists_for_article(md_file, category)
                
                if image_exists:
                    print(f"Image already exists for: {title}")
                    
                    # Check if markdown already has the image link
                    if not has_image_link_in_markdown(md_file, category, image_filename):
                        # Create image link and insert to markdown
                        image_link = f"![{title}](/images/{category}/{image_filename})"
                        
                        if insert_image_link_in_md(md_file, image_link, 1, None):
                            success_count += 1
                            print(f"Added existing image link to: {title}")
                        else:
                            print(f"Failed to add image link to: {title}")
                    else:
                        print(f"Image link already exists in markdown: {title}")
                        skip_count += 1
                else:
                    # Image doesn't exist, create new one
                    print(f"Creating new image for: {title}")
                    
                    # Choose a gradient randomly
                    gradient = random.choice(gradient_pairs)
                    direction = random.choice(['vertical', 'horizontal'])
                    
                    output_path = Path(static_path) / image_filename
                    
                    # Create images with gradient and vector overlays
                    if create_image_with_text(title, output_path, gradient, "gradient", font_path, font_size, image_size, font_color, watermark_info):
                        # Check for duplicates
                        if is_duplicate_image(output_path, Path(static_path)):
                            print(f"Duplicate image detected: {image_filename}. Skipping...")
                            os.remove(output_path)
                            continue
                        
                        # Create an image link
                        image_link = f"![{title}](/images/{category}/{image_filename})"
                        
                        # Insert a link to markdown at the beginning of the article
                        if insert_image_link_in_md(md_file, image_link, 1, None):
                            success_count += 1
                            print(f"Successfully created and linked new image: {title}")
                        else:
                            print(f"Created image but failed to add link: {title}")
                    else:
                        print(f"Failed to create image: {title}")
            
            print(f"Category '{category}' completed: {success_count} processed, {skip_count} skipped (already complete)")
        except Exception as e:
            print(f"Error processing category {category}: {e}")
            continue
        
def main():
    """Main function for automated image generation in GitHub Actions with improved error handling"""
    # Ensure all directories exist
    ensure_directory_structure()
    
    # Validate character image structure
    validate_character_structure()
    
    # The rest of the original main function...
    print("License check passed, continuing with image generator...")

    print("=" * 60)
    print("Automatic Image Generator for Hugo Articles - GitHub Mode".center(60))
    print("=" * 60)
    
    # Ensure all default configurations exist
    ensure_default_config()
    
    # Debug: Print working directory
    print(f"Working directory: {os.getcwd()}")
    print(f"Repository path: {get_repo_path()}")
    
    # Scan for articles without images
    articles_to_process = scan_for_new_articles()
    
    if not articles_to_process:
        print("There are no new articles to process.")
        return
    
    print(f"Total found {len(articles_to_process)} articles for processing.")
    
    # Debug: Print first article path
    if articles_to_process:
        print(f"Example of article path: {articles_to_process[0][0]}")
    
    # Set up default parameters with new image size (800x450 - 16:9 aspect ratio)
    font_size = 38
    font_color = "#ffffff"
    image_size = (800, 450)  # Changed to 800x450 for 16:9 aspect ratio

    # Get font size from file instead of hardcoding
    font_size = get_font_size_from_file()
    print(f"Using font size: {font_size}")
    
    # Get gradient colors
    gradient_pairs = get_gradient_colors_from_file()
    print(f"Number of gradient colors: {len(gradient_pairs)}")
    
    # Get random fonts
    font_path = get_random_font()
    if not font_path:
        print("Cannot find font. Using default font...")
        font_path = None  # Program will handle this gracefully
    else:
        print(f"Using fonts: {font_path}")
    
    # Prepare watermark with better path handling
    watermark_paths = [
        os.path.join(get_repo_path(), "image-generator", "watermark", "watermark.png"),
        os.path.join(get_repo_path(), "image-generator", "watermark.png"),
        os.path.join(get_repo_path(), "watermark.png")
    ]
    
    watermark_path = None
    for path in watermark_paths:
        if os.path.exists(path):
            watermark_path = path
            break
    
    if watermark_path:
        print(f"Watermark found: {watermark_path}")
        watermark_info = ("image", (watermark_path, 0.7, 0.1))
    else:
        print("Watermark not found. Using text as watermark.")
        watermark_info = ("text", ("Generated", 0.5, 0.1))
    
    success_count = 0
    skip_count = 0
    
    for md_file, category in articles_to_process:
        try:
            title = extract_title_from_md(md_file)
            safe_filename = sanitize_filename(title)
            image_filename = f"{safe_filename}.jpg"  # Changed to .jpg extension
            
            # Check if image already exists
            image_exists, image_path, _ = check_image_exists_for_article(md_file, category)
            
            if image_exists:
                print(f"Image already exists for: {title}")
                
                # Check if markdown already has the image link
                if not has_image_link_in_markdown(md_file, category, image_filename):
                    # Create image link and insert to markdown
                    image_link = f"![{title}](/images/{category}/{image_filename})"
                    
                    if insert_image_link_in_md(md_file, image_link, 1, None):
                        success_count += 1
                        print(f"Added existing image link to: {title}")
                    else:
                        print(f"Failed to add image link to: {title}")
                else:
                    print(f"Image and link already exist for: {title}")
                    skip_count += 1
            else:
                # Image doesn't exist, create new one
                print(f"Creating new image for: {title}")
                
                # Choose a gradient randomly
                gradient = random.choice(gradient_pairs)
                direction = random.choice(['vertical', 'horizontal'])
                
                # Prepare the output directory
                output_dir = Path(get_static_category_path(category))
                os.makedirs(output_dir, exist_ok=True)
                
                output_path = output_dir / image_filename
                
                # Create images with gradient and vector overlays
                result = create_image_with_text(title, output_path, gradient, "gradient", font_path, font_size, image_size, font_color, watermark_info, category)
                print(f"Image creation result: {'Success' if result else 'Failed'}")
                
                if result and os.path.exists(output_path):
                    # Create an image link
                    image_link = f"![{title}](/images/{category}/{image_filename})"
                    
                    # Insert a link to markdown at the beginning of the article
                    if insert_image_link_in_md(md_file, image_link, 1, None):
                        success_count += 1
                        print(f"Successfully created and linked new image: {title}")
                    else:
                        print(f"Created image but failed to insert link into article: {title}")
                else:
                    print(f"Failed to create image: {output_path}")
        except Exception as e:
            print(f"Error processing article {md_file}: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"Completed! {success_count} processed successfully, {skip_count} skipped (already complete) out of {len(articles_to_process)} total articles.")

if __name__ == "__main__":
    main()