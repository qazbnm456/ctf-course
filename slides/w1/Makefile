

all: index.html

index.html: index.md template-revealjs.html
	pandoc -t revealjs --template=template-revealjs.html --standalone --no-highlight \
          --variable theme="my" --variable transition="linear" index.md -o index.html


