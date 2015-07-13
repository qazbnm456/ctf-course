<form>
<input type="text" name="a"></input>
<input type="text" name="b"></input>
<button type="submit">Submit</button>
</form>

<?php
$prefix = "ntucsie";
$a = $prefix . $_GET["a"];
$b = $prefix . $_GET["b"];
if ($a == $b);
else if (md5($a) == md5($b)) echo file_get_contents("flag");
else echo "fail";
?>
