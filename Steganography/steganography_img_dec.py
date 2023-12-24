"""
스테가노그래피 메시지 추출 코드
"""
from PIL import Image
import numpy as np

#===================================================================================================
# decode_bits_from_pixels: 픽셀에서 특정값을 추출하는 함수
#
# input
# pixels: 이미지의 픽셀 정보
# number_of_bits: 추출할 비트 수
# pixel_index: 픽셀의 시작 인덱스
#
# output
# decoded_value: 추출 값
# ===================================================================================================
def decode_bits_from_pixels(pixels, number_of_bits, pixel_index):
    decoded_value = 0
    i = 0
    while i < number_of_bits:
        bit = pixels[pixel_index][2] & 1
        decoded_value |= bit << i
        i += 1
        pixel_index += 1
    
    return decoded_value

#===================================================================================================
# decode: 이미지에서 메세지를 추출하는 함수
#
# input
# img_path: 이미지 경로
#===================================================================================================
def decode(img_path):
    img_file = Image.open('test.png')
    img = img_file.convert("RGBA")
    temp_pixel = np.array(img)

    w, h = img.size
    pixels = []
    for i in range(h):
        for j in range(w):
            pixels.append(temp_pixel[i][j])

    length = decode_bits_from_pixels(pixels, 32, 0)
    pixel_index = 0
    pixel_index += 32

    data = ""
    byte_index = 0
    while byte_index < length:
            decoded_value = decode_bits_from_pixels(pixels, 8, pixel_index)
            data += chr(decoded_value)
            byte_index += 1
            pixel_index += 8

    print(data)

def main():
    decode('test.png')

if __name__ == '__main__':
    main()
