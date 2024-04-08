from PIL import Image
import imagehash
import os


def find_similar_images(target_image_path, folder_path, threshold=5):
    
    target_hash = imagehash.average_hash(Image.open(target_image_path))

    
    similar_images = []
    for filename in os.listdir(folder_path):
        if filename.endswith(('.jpg', '.jpeg', '.png')):  
            file_path = os.path.join(folder_path, filename)
           
            try:
                current_hash = imagehash.average_hash(Image.open(file_path))
               
                if target_hash - current_hash <= threshold:
                    similar_images.append(file_path)
            except Exception as e:
                print(f"Error processing {file_path}: {e}")

    return similar_images


target_image_path = "fuzzy/image.jpg"
folder_path = "fuzzy-images" 
similar_images = find_similar_images(target_image_path, folder_path)


if similar_images:
    print("Similar images found:")
    for image in similar_images:
        print(image)
else:
    print("No similar images")