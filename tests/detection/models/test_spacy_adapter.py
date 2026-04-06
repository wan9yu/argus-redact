"""Tests for spaCy English NER adapter — mock spaCy dependency."""

from unittest.mock import MagicMock, patch


class TestSpaCyAdapter:
    @patch.dict("sys.modules", {"spacy": MagicMock()})
    def test_should_import_without_error(self):
        from argus_redact.lang.en.ner_adapter import SpaCyAdapter

        adapter = SpaCyAdapter()
        assert adapter is not None

    @patch.dict("sys.modules", {"spacy": MagicMock()})
    def test_should_detect_person_name(self):
        from argus_redact.lang.en.ner_adapter import SpaCyAdapter

        adapter = SpaCyAdapter()
        mock_nlp = MagicMock()
        mock_doc = MagicMock()
        mock_ent = MagicMock()
        mock_ent.text = "John"
        mock_ent.label_ = "PERSON"
        mock_ent.start_char = 0
        mock_ent.end_char = 4
        mock_doc.ents = [mock_ent]
        mock_nlp.return_value = mock_doc
        adapter._nlp = mock_nlp

        results = adapter.detect("John went to New York")

        persons = [r for r in results if r.type == "person"]
        assert len(persons) >= 1
        assert persons[0].text == "John"

    @patch.dict("sys.modules", {"spacy": MagicMock()})
    def test_should_detect_location(self):
        from argus_redact.lang.en.ner_adapter import SpaCyAdapter

        adapter = SpaCyAdapter()
        mock_nlp = MagicMock()
        mock_doc = MagicMock()
        mock_ent = MagicMock()
        mock_ent.text = "New York"
        mock_ent.label_ = "GPE"
        mock_ent.start_char = 13
        mock_ent.end_char = 21
        mock_doc.ents = [mock_ent]
        mock_nlp.return_value = mock_doc
        adapter._nlp = mock_nlp

        results = adapter.detect("John went to New York")

        locations = [r for r in results if r.type == "location"]
        assert len(locations) >= 1
        assert locations[0].text == "New York"

    @patch.dict("sys.modules", {"spacy": MagicMock()})
    def test_should_detect_organization(self):
        from argus_redact.lang.en.ner_adapter import SpaCyAdapter

        adapter = SpaCyAdapter()
        mock_nlp = MagicMock()
        mock_doc = MagicMock()
        mock_ent = MagicMock()
        mock_ent.text = "Google"
        mock_ent.label_ = "ORG"
        mock_ent.start_char = 15
        mock_ent.end_char = 21
        mock_doc.ents = [mock_ent]
        mock_nlp.return_value = mock_doc
        adapter._nlp = mock_nlp

        results = adapter.detect("She works at Google")

        orgs = [r for r in results if r.type == "organization"]
        assert len(orgs) >= 1
        assert orgs[0].text == "Google"

    @patch.dict("sys.modules", {"spacy": MagicMock()})
    def test_should_skip_unknown_label(self):
        from argus_redact.lang.en.ner_adapter import SpaCyAdapter

        adapter = SpaCyAdapter()
        mock_nlp = MagicMock()
        mock_doc = MagicMock()
        mock_ent = MagicMock()
        mock_ent.text = "Monday"
        mock_ent.label_ = "DATE"
        mock_ent.start_char = 0
        mock_ent.end_char = 6
        mock_doc.ents = [mock_ent]
        mock_nlp.return_value = mock_doc
        adapter._nlp = mock_nlp

        results = adapter.detect("Monday is busy")

        assert results == []

    @patch.dict("sys.modules", {"spacy": MagicMock()})
    def test_should_return_empty_when_no_entities(self):
        from argus_redact.lang.en.ner_adapter import SpaCyAdapter

        adapter = SpaCyAdapter()
        mock_nlp = MagicMock()
        mock_doc = MagicMock()
        mock_doc.ents = []
        mock_nlp.return_value = mock_doc
        adapter._nlp = mock_nlp

        results = adapter.detect("Nothing to see here")

        assert results == []

    @patch.dict("sys.modules", {"spacy": MagicMock()})
    def test_should_return_empty_when_empty_text(self):
        from argus_redact.lang.en.ner_adapter import SpaCyAdapter

        adapter = SpaCyAdapter()

        results = adapter.detect("")

        assert results == []


class TestCreateAdapter:
    @patch.dict("sys.modules", {"spacy": MagicMock()})
    def test_should_return_spacy_adapter(self):
        from argus_redact.lang.en.ner_adapter import create_adapter

        adapter = create_adapter()
        assert adapter is not None
