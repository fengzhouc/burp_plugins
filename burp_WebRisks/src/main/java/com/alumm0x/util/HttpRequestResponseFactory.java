package com.alumm0x.util;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class HttpRequestResponseFactory implements IHttpRequestResponse {


    private byte[] request;
    private byte[] response;
    private IHttpService httpService;
    private String comment;
    private String highlight;

    public HttpRequestResponseFactory(byte[] request, byte[] response, IHttpService httpService){
        this.request = request;
        this.response = response;
        this.httpService = httpService;
    }

    public HttpRequestResponseFactory(){
        //无参构造函数
    }

    @Override
    public byte[] getRequest() {
        return this.request;
    }

    @Override
    public void setRequest(byte[] bytes) {
        this.request = bytes;
    }

    @Override
    public byte[] getResponse() {
        return this.response;
    }

    @Override
    public void setResponse(byte[] bytes) {
        this.response = bytes;
    }

    @Override
    public String getComment() {
        return this.comment;
    }

    @Override
    public void setComment(String s) {
        this.comment = s;
    }

    @Override
    public String getHighlight() {
        return this.highlight;
    }

    @Override
    public void setHighlight(String s) {
        this.highlight = s;
    }

    @Override
    public IHttpService getHttpService() {
        return this.httpService;
    }

    @Override
    public void setHttpService(IHttpService iHttpService) {
        this.httpService = iHttpService;
    }
}
