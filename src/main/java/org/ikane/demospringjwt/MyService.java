package org.ikane.demospringjwt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Slf4j
@Service
public class MyService {
	public void process() {
		log.info("processing...");
		ServletRequestAttributes requestAttributes = (ServletRequestAttributes)RequestContextHolder.getRequestAttributes();
		String param1 = requestAttributes.getRequest().getParameter("param1");
		log.info("Param1: {}", param1);
	}
}
