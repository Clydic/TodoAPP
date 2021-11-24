<?php

namespace App\Controller;

use DateTime;
use DateInterval;
use Dompdf\Dompdf;
use Dompdf\Options;
use App\Entity\Task;
use App\Form\TaskType;
use App\Repository\TaskRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class TaskController extends AbstractController
{
    /**
     * @var TaskRepository
     */
    private $repository;

    /**
     * @var EntityManagerInterface
     */
    private $manager;

    public function __construct(TaskRepository $repository, EntityManagerInterface $manager)
    {
        $this->repository = $repository;
        $this->manager = $manager;
    }

    /**
     * @Route("/task/listing", name="task_listing")
     */
    public function index(): Response
    {
        $user = $this->getUser();
        $role = $user->getRoles();
        $admin = "ROLE_ADMIN";
        $id = $user->getId();

        if (in_array($admin, $role)) {
            $tasks = $this->repository->findAll();
        } else {
            $tasks = $this->repository->findBy(['user' => $id]);
        }

        return $this->render('task/index.html.twig', [
            'tasks' => $tasks,
        ]);
    }

    /**
     * @Route("/task/create", name="task_create")
     * @Route("/task/update/{id}", name="task_update", requirements={"id"="\d+"})
     */
    public function Task(Task $task = null, Request $request)
    {

        if (!$task) {
            $task = new Task;
            $task->setCreatedAt(new \DateTime());

            $user = $this->getUser();
            $task->setUser($user);
        }


        $form = $this->createForm(TaskType::class, $task, []);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {

            $this->manager->persist($task);
            $this->manager->flush();

            return $this->redirectToRoute('task_listing');
        }

        return $this->render('task/create.html.twig', [
            'form' => $form->createView()
        ]);
    }

    /**
     * @Route("/task/delete/{id}", name="task_delete", requirements={"id"="\d+"})
     */
    public function deleteTask(Task $task)
    {
        $this->manager->remove($task);
        $this->manager->flush();

        $this->addFlash(
            'Delete',
            'L\'action a bien effacée'
        );
        $this->addFlash(
            'success',
            'L\'action a bien été effectuée'
        );

        return $this->redirectToRoute('task_listing');
    }
    /**
     * 
     *@Route("/task/listing/download", name="task_download")
     */
    public function dowloadPdf()
    {
        $tasks = $this->repository->findAll();
        // Gestion des options
        $pdfoption = new Options;
        $pdfoption->set('default', "Arial");
        // $pdfoption->setIsRemoteEnabled(true);

        // On va instantier le domPdf pour créer le téléchargement
        $dompdf = new Dompdf($pdfoption);

        $html = $this->renderView('pdf/pdfdownload.html.twig', [
            'tasks' => $tasks,

        ]);
        $dompdf->loadHtml($html);
        $dompdf->setPaper('A4', 'landscape');
        $dompdf->render();

        $fichier = 'J\'dore les pdfs';
        $dompdf->stream($fichier, [
            'Attachement' => true
        ]);
    }
}
