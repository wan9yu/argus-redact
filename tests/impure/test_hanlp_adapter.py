"""Tests for HanLP NER adapter — mock HanLP dependency."""

from unittest.mock import MagicMock, patch


class TestHanLPAdapter:
    """HanLP Chinese NER adapter."""

    def _make_adapter(self, mock_hanlp):
        from argus_redact.lang.zh.ner_adapter import HanLPAdapter

        return HanLPAdapter()

    @patch.dict("sys.modules", {"hanlp": MagicMock()})
    def test_should_import_without_error(self):
        from argus_redact.lang.zh.ner_adapter import HanLPAdapter

        adapter = HanLPAdapter()
        assert adapter is not None

    @patch.dict("sys.modules", {"hanlp": MagicMock()})
    def test_should_detect_person_name(self):
        from argus_redact.lang.zh.ner_adapter import HanLPAdapter

        adapter = HanLPAdapter()
        mock_model = MagicMock()
        mock_model.return_value = {
            "ner/msra": [("张三", "PERSON", 0, 2)],
        }
        adapter._model = mock_model

        results = adapter.detect("张三去了北京")

        persons = [r for r in results if r.type == "person"]
        assert len(persons) >= 1
        assert persons[0].text == "张三"

    @patch.dict("sys.modules", {"hanlp": MagicMock()})
    def test_should_detect_location(self):
        from argus_redact.lang.zh.ner_adapter import HanLPAdapter

        adapter = HanLPAdapter()
        mock_model = MagicMock()
        mock_model.return_value = {
            "ner/msra": [("北京", "LOCATION", 3, 5)],
        }
        adapter._model = mock_model

        results = adapter.detect("张三去了北京")

        locations = [r for r in results if r.type == "location"]
        assert len(locations) >= 1
        assert locations[0].text == "北京"

    @patch.dict("sys.modules", {"hanlp": MagicMock()})
    def test_should_detect_organization(self):
        from argus_redact.lang.zh.ner_adapter import HanLPAdapter

        adapter = HanLPAdapter()
        mock_model = MagicMock()
        mock_model.return_value = {
            "ner/msra": [("阿里巴巴", "ORGANIZATION", 2, 6)],
        }
        adapter._model = mock_model

        results = adapter.detect("在阿里巴巴工作")

        orgs = [r for r in results if r.type == "organization"]
        assert len(orgs) >= 1
        assert orgs[0].text == "阿里巴巴"

    @patch.dict("sys.modules", {"hanlp": MagicMock()})
    def test_should_detect_multiple_entities(self):
        from argus_redact.lang.zh.ner_adapter import HanLPAdapter

        adapter = HanLPAdapter()
        mock_model = MagicMock()
        mock_model.return_value = {
            "ner/msra": [
                ("张三", "PERSON", 0, 2),
                ("李四", "PERSON", 3, 5),
                ("星巴克", "ORGANIZATION", 6, 9),
            ],
        }
        adapter._model = mock_model

        results = adapter.detect("张三和李四在星巴克聊天")

        assert len(results) == 3
        types = {r.type for r in results}
        assert "person" in types
        assert "organization" in types

    @patch.dict("sys.modules", {"hanlp": MagicMock()})
    def test_should_return_empty_when_no_entities(self):
        from argus_redact.lang.zh.ner_adapter import HanLPAdapter

        adapter = HanLPAdapter()
        mock_model = MagicMock()
        mock_model.return_value = {"ner/msra": []}
        adapter._model = mock_model

        results = adapter.detect("今天天气不错")

        assert results == []

    @patch.dict("sys.modules", {"hanlp": MagicMock()})
    def test_should_map_entity_types_correctly(self):
        from argus_redact.lang.zh.ner_adapter import HanLPAdapter

        adapter = HanLPAdapter()
        mock_model = MagicMock()
        mock_model.return_value = {
            "ner/msra": [
                ("张三", "PERSON", 0, 2),
                ("北京", "LOCATION", 3, 5),
                ("腾讯", "ORGANIZATION", 6, 8),
            ],
        }
        adapter._model = mock_model

        results = adapter.detect("张三在北京的腾讯工作")

        type_map = {r.text: r.type for r in results}
        assert type_map["张三"] == "person"
        assert type_map["北京"] == "location"
        assert type_map["腾讯"] == "organization"

    @patch.dict("sys.modules", {"hanlp": MagicMock()})
    def test_should_set_confidence_for_all_entities(self):
        from argus_redact.lang.zh.ner_adapter import HanLPAdapter

        adapter = HanLPAdapter()
        mock_model = MagicMock()
        mock_model.return_value = {
            "ner/msra": [("张三", "PERSON", 0, 2)],
        }
        adapter._model = mock_model

        results = adapter.detect("张三")

        assert results[0].confidence > 0


class TestHanLPAdapterEdgeCases:
    """Edge cases for robustness."""

    @patch.dict("sys.modules", {"hanlp": MagicMock()})
    def test_should_return_empty_when_empty_text(self):
        from argus_redact.lang.zh.ner_adapter import HanLPAdapter

        adapter = HanLPAdapter()

        results = adapter.detect("")

        assert results == []

    @patch.dict("sys.modules", {"hanlp": MagicMock()})
    def test_should_skip_unknown_label(self):
        from argus_redact.lang.zh.ner_adapter import HanLPAdapter

        adapter = HanLPAdapter()
        mock_model = MagicMock()
        mock_model.return_value = {
            "ner/msra": [("something", "UNKNOWN_TYPE", 0, 1)],
            "tok/fine": ["something"],
        }
        adapter._model = mock_model

        results = adapter.detect("something")

        assert results == []

    @patch.dict("sys.modules", {"hanlp": MagicMock()})
    def test_should_fallback_when_token_offsets_invalid(self):
        from argus_redact.lang.zh.ner_adapter import HanLPAdapter

        adapter = HanLPAdapter()
        mock_model = MagicMock()
        mock_model.return_value = {
            "ner/msra": [("张三", "PERSON", 99, 100)],
            "tok/fine": ["张三", "说话"],
        }
        adapter._model = mock_model

        results = adapter.detect("张三说话")

        assert len(results) == 1
        assert results[0].text == "张三"
        assert results[0].start == 0
        assert results[0].end == 2


class TestCreateAdapter:
    @patch.dict("sys.modules", {"hanlp": MagicMock()})
    def test_should_return_hanlp_adapter(self):
        from argus_redact.lang.zh.ner_adapter import create_adapter

        adapter = create_adapter()
        assert adapter is not None
