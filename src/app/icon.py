from PIL import Image, ImageDraw
import os

def create_icon():
    # 创建一个64x64的透明背景图像
    img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # 定义颜色
    primary_color = (76, 175, 80)  # 绿色
    secondary_color = (33, 150, 243)  # 蓝色
    
    # 绘制箭头和端口符号
    # 左侧端口
    draw.rectangle([10, 20, 20, 44], fill=primary_color)
    # 右侧端口
    draw.rectangle([44, 20, 54, 44], fill=secondary_color)
    
    # 绘制连接箭头
    points = [
        (22, 32),  # 左起点
        (42, 32),  # 右终点
        (36, 26),  # 右上箭头
        (42, 32),  # 右中点
        (36, 38),  # 右下箭头
    ]
    draw.line(points, fill=primary_color, width=3)
    
    # 保存图标
    icon_path = os.path.join(os.path.dirname(__file__), 'icon.png')
    img.save(icon_path)
    
if __name__ == '__main__':
    create_icon() 