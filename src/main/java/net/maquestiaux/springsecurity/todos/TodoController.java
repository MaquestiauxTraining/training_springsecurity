package net.maquestiaux.springsecurity.todos;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.security.RolesAllowed;

@RestController
public class TodoController {

	private Logger logger = LoggerFactory.getLogger(getClass());

	private static final List<Todo> TODOLIST = List.of(new Todo("maqueje", "Course 1"),
			new Todo("maqueje", "Course 2"));

	public TodoController() {
		// TODO Auto-generated constructor stub
	}

	@GetMapping("/todos")
	public List<Todo> retrieveAllTodos() {
		return TODOLIST;
	}

	@GetMapping("/users/{username}/todos")
	@PreAuthorize("hasRole('USER') and #username == authentication.name")
	@PostAuthorize("returnObject.username == 'in28minutes'")
	@RolesAllowed({ "ADMIN", "USER" })
	@Secured({ "ROLE_ADMIN", "ROLE_USER" })
	public Todo retrieveTodosForSpecificUser(@PathVariable("username") String username) {
		return TODOLIST.get(0);
	}

	@PostMapping("/users/{username}/todos")
	public void addTodosForSpecificUser(@PathVariable("username") String username, @RequestBody Todo todo) {
		logger.info("Creating a Todo {} for {}", todo, username);
	}

}

record Todo(String username, String description) {
}