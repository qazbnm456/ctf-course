

all: format-string.html rop.html

format-string.html: format-string.md template-revealjs.html
	pandoc -t revealjs --template=template-revealjs.html --standalone --no-highlight \
          --variable theme="my" --variable transition="linear" format-string.md -o format-string.html

rop.html: rop.md template-revealjs.html
	pandoc -t revealjs --template=template-revealjs.html --standalone --no-highlight \
          --variable theme="my" --variable transition="linear" rop.md -o rop.html



