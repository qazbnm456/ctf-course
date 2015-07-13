

all: exp.html

exp.html: exp.md template-revealjs.html
	pandoc -t revealjs --template=template-revealjs.html --standalone --no-highlight \
          --variable theme="my" --variable transition="linear" exp.md -o exp.html



