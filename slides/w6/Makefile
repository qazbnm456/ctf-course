

all: heap.html

heap.html: heap.md template-revealjs.html
	pandoc -t revealjs --template=template-revealjs.html --standalone --no-highlight \
          --variable theme="my" --variable transition="linear" heap.md -o heap.html



