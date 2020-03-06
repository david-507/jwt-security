package org.dmace.security.demo.errors;

import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Component
public class ApiErrorAttributes extends DefaultErrorAttributes {

	@Override
	public Map<String, Object> getErrorAttributes(WebRequest webRequest, boolean includeStackTrace) {
		Map<String, Object> allErrorAttributes = super.getErrorAttributes(webRequest, includeStackTrace);

		Map<String, Object> errorAttributes = new HashMap<>();
		int statusCode = (int) allErrorAttributes.get("status");
		errorAttributes.put("status", HttpStatus.valueOf(statusCode));
		errorAttributes.put("date", LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss")));

		String message = "";
		
		Throwable throwable = getError(webRequest);
		if(!Objects.isNull(throwable)) {
			if (throwable instanceof ResponseStatusException) {
				ResponseStatusException responseStatusException = (ResponseStatusException) throwable;
				message = responseStatusException.getReason() == null ? "" : responseStatusException.getReason();
			} else {
				if (throwable.getCause() != null)
					message = throwable.getCause().getMessage() == null ? throwable.getCause().toString() : throwable.getCause().getMessage();
				else
					message = throwable.toString();
			}
		}

		
		errorAttributes.put("message", message);
		
		return errorAttributes;
	}

}