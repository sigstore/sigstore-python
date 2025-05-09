[1mdiff --git a/test/unit/test_models.py b/test/unit/test_models.py[m
[1mindex 95f297f..088e86f 100644[m
[1m--- a/test/unit/test_models.py[m
[1m+++ b/test/unit/test_models.py[m
[36m@@ -30,12 +30,13 @@[m [mfrom sigstore.models import ([m
 [m
 [m
 class TestLogEntry:[m
[31m-    def test_missing_inclusion_proof(self):[m
[32m+[m[32m    @pytest.mark.parametrize('integrated_time', [0, 1746819403])[m
[32m+[m[32m    def test_missing_inclusion_proof(self, integrated_time: int):[m
         with pytest.raises(ValueError, match=r"inclusion_proof"):[m
             LogEntry([m
                 uuid="fake",[m
                 body=b64encode(b"fake"),[m
[31m-                integrated_time=0,[m
[32m+[m[32m                integrated_time=integrated_time,[m
                 log_id="1234",[m
                 log_index=1,[m
                 inclusion_proof=None,[m
