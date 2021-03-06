package top.iaminlearn.exception;

import org.apache.shiro.ShiroException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import top.iaminlearn.util.BaseResponse;

import javax.servlet.http.HttpServletRequest;

/**
 * Date: 2021/5/11 18:47
 */
@RestControllerAdvice
/**
 * 处理全局异常
 */
public class ExceptionController {

    // 捕捉shiro的异常
    @ExceptionHandler(ShiroException.class)
    public Object handleShiroException(ShiroException e) {
        BaseResponse<Object> ret = new BaseResponse<Object>();
        ret.setErrCode(401);
        ret.setMsg(e.getMessage());
        return ret;
    }

    // 捕捉其他所有异常
    @ExceptionHandler(Exception.class)
    public Object globalException(HttpServletRequest request, Throwable ex) {
        BaseResponse<Object> ret = new BaseResponse<Object>();
        ret.setErrCode(401);
        ret.setMsg(ex.getMessage());
        return ret;
    }

}
