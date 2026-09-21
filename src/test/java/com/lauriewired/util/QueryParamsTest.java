package com.lauriewired.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

/**
 * Unit tests for {@link QueryParams}. These run without a Ghidra runtime.
 */
public class QueryParamsTest {

    @Test
    public void parsesMultiplePairs() {
        Map<String, String> params = QueryParams.parseQuery("offset=10&limit=100");

        assertEquals(2, params.size());
        assertEquals("10", params.get("offset"));
        assertEquals("100", params.get("limit"));
    }

    @Test
    public void keepsValuesContainingEqualsSigns() {
        Map<String, String> params = QueryParams.parseQuery("filter=a=b&offset=0");

        assertEquals("a=b", params.get("filter"));
        assertEquals("0", params.get("offset"));
    }

    @Test
    public void ignoresPairsWithoutEqualsSign() {
        Map<String, String> params = QueryParams.parseQuery("flag&offset=1");

        assertFalse(params.containsKey("flag"));
        assertEquals(1, params.size());
        assertEquals("1", params.get("offset"));
    }

    @Test
    public void decodesPercentEscapesAndPlusSigns() {
        Map<String, String> params = QueryParams.parseQuery("name=hello%20world&city=a+b");

        assertEquals("hello world", params.get("name"));
        assertEquals("a b", params.get("city"));
    }

    @Test
    public void decodesKeysAsWellAsValues() {
        Map<String, String> params = QueryParams.parseQuery("my%20key=value");

        assertEquals("value", params.get("my key"));
    }

    @Test
    public void decodesEscapedAmpersandInsideValue() {
        Map<String, String> params = QueryParams.parseQuery("a=1%262&b=3");

        assertEquals("1&2", params.get("a"));
        assertEquals("3", params.get("b"));
    }

    @Test
    public void skipsMalformedPercentEscapes() {
        Map<String, String> params = QueryParams.parseQuery("bad=%zz&good=1");

        assertEquals(1, params.size());
        assertEquals("1", params.get("good"));
    }

    @Test
    public void returnsEmptyMapForNullOrEmptyInput() {
        assertTrue(QueryParams.parseQuery(null).isEmpty());
        assertTrue(QueryParams.parseQuery("").isEmpty());
        assertTrue(QueryParams.parseBody(null).isEmpty());
        assertTrue(QueryParams.parseBody("").isEmpty());
    }

    @Test
    public void parsesFormBodiesLikeQueries() {
        Map<String, String> params = QueryParams.parseBody("oldName=foo&newName=bar&value=a=b");

        assertEquals("foo", params.get("oldName"));
        assertEquals("bar", params.get("newName"));
        assertEquals("a=b", params.get("value"));
    }

    @Test
    public void keepsValueWithEmptyString() {
        Map<String, String> params = QueryParams.parseQuery("name=");

        assertEquals(1, params.size());
        assertEquals("", params.get("name"));
    }
}
