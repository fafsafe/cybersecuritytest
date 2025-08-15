#include <opencv2/opencv.hpp>
#include <iostream>

using namespace cv;
using namespace std;

void embedWatermark(const Mat& image, const Mat& watermark, Mat& output, double alpha) {
    Mat watermark_resized;
    resize(watermark, watermark_resized, Size(image.cols, image.rows));
    addWeighted(image, 1.0 - alpha, watermark_resized, alpha, 0.0, output);
}

void extractWatermark(const Mat& original, const Mat& watermarked, const Mat& output, double alpha) {
    Mat original_weighted, watermarked_weighted;
    addWeighted(original, 1.0 - alpha, original, alpha, 0.0, original_weighted);
    subtract(watermarked, original_weighted, output);
}

void testRobustness(const Mat& image) {
    // 翻转
    Mat flipped;
    flip(image, flipped, 1); // 水平翻转
    imwrite("flipped_watermarked_image.jpg", flipped);

    // 平移
    Mat translated;
    Mat M = (Mat_<double>(2, 3) << 1, 0, 50, 0, 1, 50); // 平移矩阵
    warpAffine(image, translated, M, image.size());
    imwrite("translated_watermarked_image.jpg", translated);

    // 截取
    Mat cropped = image(Rect(50, 50, 100, 100)); // 截取中间区域
    imwrite("cropped_watermarked_image.jpg", cropped);

    // 调对比度
    Mat adjusted_contrast;
    image.convertTo(adjusted_contrast, -1, 2.0, 0); // 对比度加倍
    imwrite("adjusted_contrast_watermarked_image.jpg", adjusted_contrast);
}

int main() {
    // 读取图像和水印
    Mat original_image = imread("path_to_image.jpg");
    Mat watermark = imread("path_to_watermark.png");

    if (original_image.empty() || watermark.empty()) {
        cout << "Could not open or find the images!" << endl;
        return -1;
    }

    // 嵌入水印
    Mat watermarked_image;
    embedWatermark(original_image, watermark, watermarked_image, 0.3);
    imwrite("watermarked_image.jpg", watermarked_image);

    // 提取水印
    Mat extracted_watermark;
    extractWatermark(original_image, watermarked_image, extracted_watermark, 0.3);
    imwrite("extracted_watermark.png", extracted_watermark);

    // 进行鲁棒性测试
    testRobustness(watermarked_image);

    return 0;
}
