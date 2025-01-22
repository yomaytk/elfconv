cd $(dirname $0)
docker build . -t elfconv-image && docker run -it --rm -v $(pwd):/pwd --name elfconv-container elfconv-image