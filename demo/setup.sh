#!/usr/bin/env bash
# HF Space setup script — download spaCy models
python -m spacy download zh_core_web_sm
python -m spacy download en_core_web_sm
python -m spacy download ja_core_news_sm
python -m spacy download ko_core_news_sm
python -m spacy download de_core_news_sm
python -m spacy download xx_ent_wiki_sm
