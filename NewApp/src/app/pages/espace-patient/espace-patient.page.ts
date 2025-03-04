import { Component, OnInit } from '@angular/core';
import { AppComponent } from 'src/app/app.component';


@Component({
  selector: 'app-espace-patient',
  templateUrl: './espace-patient.page.html',
  styleUrls: ['./espace-patient.page.scss'],
  standalone: false,
})
export class EspacePatientPage implements OnInit {

  constructor(private appComponent: AppComponent) { }

  ngOnInit() {
  }

   /* Ouvre le menu profil. */
   openProfileMenu(event: Event) {
    this.appComponent.openProfileMenu(event);
  } 

}
