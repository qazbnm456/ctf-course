

all: bp.html

%.html: %.md template-revealjs.html
	pandoc -t revealjs --template=template-revealjs.html --standalone --no-highlight \
          --variable theme="my" --variable transition="linear" $< -o $@

