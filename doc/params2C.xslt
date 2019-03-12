<?xml version="1.0"?>

<!--
Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.

Licensed under the Apache License 2.0 (the "License").  You may not use
this file except in compliance with the License.  You can obtain a copy
in the file LICENSE in the source distribution or at
https://www.openssl.org/source/license.html
-->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns="https://www.openssl.org">


  <xsl:output method="text" omit-xml-declaration="yes" standalone="no"
              indent="no" media-type="text/plain"/> 

  <xsl:strip-space elements="*"/>

  <xsl:template match="/">
    <xsl:apply-templates/>
  </xsl:template>

  <xsl:template match="parameters">
    <xsl:text>const OSSL_PARAM OSSL_PARAM_DEFS_</xsl:text><xsl:value-of select="@algorithm"/><xsl:text>[] = {
</xsl:text>
    <xsl:apply-templates/>
    <xsl:text>    { NULL, 0, NULL, 0, NULL },
</xsl:text>
    <xsl:text>};
</xsl:text>
  </xsl:template>

  <xsl:template match="comment()"/>

  <xsl:template match="parameter">
    <xsl:text>    { </xsl:text>
    <xsl:call-template name="name"/><xsl:text>, </xsl:text>
    <xsl:call-template name="datatype"/><xsl:text>, </xsl:text>
    <xsl:text>NULL, </xsl:text>
    <xsl:call-template name="datasize"/><xsl:text>, </xsl:text>
    <xsl:text>NULL },
</xsl:text>
  </xsl:template>

  <xsl:template name="name">
    <xsl:text>"</xsl:text><xsl:value-of select="name"/><xsl:text>"</xsl:text>
  </xsl:template>

  <xsl:template name="datatype">
    <xsl:choose>
      <xsl:when test="datatype = 'integer'">
        <xsl:text>OSSL_PARAM_INTEGER</xsl:text>
      </xsl:when>
      <xsl:when test="datatype = 'unsigned integer'">
        <xsl:text>OSSL_PARAM_UNSIGNED_INTEGER</xsl:text>
      </xsl:when>
      <xsl:when test="datatype = 'real'">
        <xsl:text>OSSL_PARAM_REAL</xsl:text>
      </xsl:when>
      <xsl:when test="datatype = 'utf8 string'">
        <xsl:text>OSSL_PARAM_UTF8_STRING</xsl:text>
      </xsl:when>
      <xsl:when test="datatype = 'octet string'">
        <xsl:text>OSSL_PARAM_OCTET_STRING</xsl:text>
      </xsl:when>
      <xsl:when test="datatype = 'utf8 pointer'">
        <xsl:text>OSSL_PARAM_UTF8_PTR</xsl:text>
      </xsl:when>
      <xsl:when test="datatype = 'octet pointer'">
        <xsl:text>OSSL_PARAM_OCTET_PTR</xsl:text>
      </xsl:when>
      <xsl:otherwise>...</xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="datasize">
    <xsl:choose>
      <xsl:when test="count(datasize) > 0">
        <xsl:value-of select="datasize"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>0</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:if test="unit = 'bits'">
      <xsl:text>* 8</xsl:text>
    </xsl:if>
  </xsl:template>
</xsl:stylesheet>
